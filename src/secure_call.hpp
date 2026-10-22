#pragma once

#include <exception>
#include <functional>
#include <optional>
#include <system_error>
#include <type_traits>

#include "secure_memory.hpp"

#ifdef __linux__
#include <pthread.h>
#endif

namespace keycore::detail {

// Crypto libraries also put derived keys and intermediate values on the stack.
// A dedicated, locked stack covers those copies as well as our protected heap.
template <typename Function> auto secure_call(Function function) -> std::invoke_result_t<Function> {
    initialize_secure_memory();
#ifdef __linux__
    using result_type = std::invoke_result_t<Function>;
    struct state_type {
        Function &function;
        std::optional<result_type> result;
        std::exception_ptr error;
    } state{function, {}, {}};
    secure_buffer stack(1024 * 1024);
    pthread_attr_t attributes;
    int result = pthread_attr_init(&attributes);
    if (result != 0)
        throw std::system_error(result, std::generic_category(), "Cannot prepare protected stack");
    result = pthread_attr_setstack(&attributes, stack.data(), stack.size());
    pthread_t thread{};
    if (result == 0) {
        result = pthread_create(
            &thread, &attributes,
            [](void *argument) -> void * {
                auto &state = *static_cast<state_type *>(argument);
                try {
                    state.result.emplace(state.function());
                } catch (...) {
                    state.error = std::current_exception();
                }
                return nullptr;
            },
            &state);
    }
    pthread_attr_destroy(&attributes);
    if (result != 0)
        throw std::system_error(result, std::generic_category(), "Cannot start protected operation");
    if (pthread_join(thread, nullptr) != 0)
        std::terminate();
    if (state.error)
        std::rethrow_exception(state.error);
    return std::move(*state.result);
#else
    return function();
#endif
}

} // namespace keycore::detail
