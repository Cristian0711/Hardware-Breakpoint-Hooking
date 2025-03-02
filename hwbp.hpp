#include <winternl.h>

class hwbp {
private:
	hwbp() {};
public:
	static auto get() -> hwbp& {
		static hwbp instance;

		if (instance.nt_functions_inited == false) {
			instance.init_nt_functions();
		}

		return instance;
	}

	auto setup() noexcept -> void {
		auto handler = AddVectoredExceptionHandler(1, exception_handler);

		// garbage collector thd to remain ud in hookshark
		callbacks::get().add_callback(callbacks::callback_type::every_frame, [this]() {
			for (const auto& _hook : _hooks_map) {
				if (_hook.second.garbage_colector == false) {
					continue;
				}

				auto thread = get_current_thread();
				CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
				if (NT_SUCCESS(nt_get_context_thread(thread, &context)) == false) {
					continue;
				}

				repatch_disable_hook(&context, _hook.first, _hook.second.position);

				if (NT_SUCCESS(nt_set_context_thread(thread, &context)) == false) {
					return false;
				}

				repatch_remove_hook(_hook.first, _hook.second.position);
			}
		});
	}

	auto hook(HANDLE thread, uintptr_t address, std::function<void(PEXCEPTION_POINTERS)> fn_callback, bool repatch_active = true, bool garbage_colector = false) -> bool {
		// make sure you're not hooking the same address twice, otherwise will crash
		auto position = get_free_hook_position(address);
		if (position == -1) {
			return false;
		}

		occupied_index_count[position] = 1;

		CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
		if (NT_SUCCESS(nt_get_context_thread(thread, &context)) == false) {
			return false;
		}

		if (_hooks_map.count(address) == 0) {
			_hooks_map[address] = { fn_callback, position, repatch_active, garbage_colector };
		}

		(&context.Dr0)[position] = address;

		context.Dr7 &= ~(3ull << (16 + 4 * position));
		context.Dr7 &= ~(3ull << (18 + 4 * position));
		context.Dr7 |= 1ull << (2 * position);

		if (NT_SUCCESS(nt_set_context_thread(thread, &context)) == false) {
			return false;
		}
		
		return true;
	}

	auto hook_current_thread(uintptr_t address, std::function<void(PEXCEPTION_POINTERS)> fn_callback, bool repatch_active = true, bool garbage_colector = false) noexcept -> bool {
		return hook(get_current_thread(), address, fn_callback, repatch_active, garbage_colector);
	}

private:
	static LONG WINAPI exception_handler(PEXCEPTION_POINTERS exception_info)
	{
		if (exception_info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
			return EXCEPTION_CONTINUE_SEARCH;
		}

		hwbp::get().on_single_step(exception_info);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	auto on_single_step(PEXCEPTION_POINTERS exception_info) -> LONG {
		const auto exception_address = exception_info->ContextRecord->Eip;

		if (_hooks_map.count(exception_address) != 0) {

			const auto& hook_data = _hooks_map[exception_address];
			if (hook_data.callback != nullptr)
				std::invoke(hook_data.callback, exception_info);

			// TRIGGER ANOTHER SINGLESTEP FOR REPATCH
			if (hook_data.repatch_active == true) {
				_repatch[exception_address] = true;
				exception_info->ContextRecord->EFlags |= 0x100ui32;
			}
			else {
				repatch_remove_hook(exception_address, hook_data.position);
			}

			// DISABLE HWBP FOR EXECUTION TO CONTINUE
			repatch_disable_hook(exception_info->ContextRecord, exception_address, hook_data.position);
			nt_set_context_thread(get_current_thread(), exception_info->ContextRecord);
		}

		for (auto& place : _repatch) {
			if (place.second != true || _hooks_map.count(place.first) == 0)
				continue;

			exception_info->ContextRecord->EFlags &= ~0x100ui32;
			repatch_enable_hook(exception_info->ContextRecord, place.first, _hooks_map[place.first].position);
			place.second = false;
		}
	}

	auto repatch_remove_hook(uintptr_t address, uint8_t position) -> void{
		occupied_index_count[position] = 0;
		_hooks_map.erase(address);
	}

	auto repatch_enable_hook(PCONTEXT context, uintptr_t address, uint8_t position) -> void {
		(&context->Dr0)[position] = address;

		context->Dr7 &= ~(3ull << (16 + 4 * position));
		context->Dr7 &= ~(3ull << (18 + 4 * position));
		context->Dr7 |= 1ull << (2 * position);
	}

	auto repatch_disable_hook(PCONTEXT context, uintptr_t address, uint8_t position) -> void {
		context->ContextFlags |= WOW64_CONTEXT_DEBUG_REGISTERS;
		*(&context->Dr0 + position) = 0;
		context->Dr7 &= ~(1ll << (2 * position));
		context->Dr6 = 0;
	}

	[[nodiscard]] auto get_free_hook_position(uintptr_t address) const noexcept -> int8_t {
		if (_hooks_map.count(address) != 0) {
			return -1;
		}

		for (int8_t index = 0; index != occupied_index_count.size(); ++index) {
			if (occupied_index_count[index] == 0) {
				return index;
			}
		}

		return -1;
	}

	auto init_nt_functions() noexcept -> void {
		nt_set_context_thread = reinterpret_cast<nt_set_context_thread_t>(memory::get().pattern_scan_module(L"ntdll.dll", "B8 8D 01 00 00 BA ? ? ? ? FF D2 C2 08 00 90"));
		nt_get_context_thread = reinterpret_cast<nt_get_context_thread_t>(memory::get().pattern_scan_module(L"ntdll.dll", "B8 F3 00 00 00 BA ? ? ? ? FF D2 C2 08 00 90"));

		nt_functions_inited = true;
	}

	auto get_current_thread() const noexcept -> HANDLE {
		return reinterpret_cast<HANDLE>(-02);
	}

private:
	struct hook_data {
		hook_data() = default;

		hook_data(std::function<void(PEXCEPTION_POINTERS)> callback, int8_t position, bool repatch_active, bool garbage_colector) :
			callback(callback), position(position), repatch_active(repatch_active), garbage_colector(garbage_colector) {};

		std::function<void(PEXCEPTION_POINTERS)> callback = nullptr;
		int8_t position = -1;
		bool repatch_active = true;
		bool garbage_colector = false;
	};

	std::unordered_map<uintptr_t, hook_data> _hooks_map;
	std::array<uint8_t, 4> occupied_index_count = { 0, 0, 0, 0 };
	std::map<uintptr_t, bool> _repatch;

	bool nt_functions_inited = { false };
	using nt_set_context_thread_t = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, CONTEXT* Context);
	using nt_get_context_thread_t = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, const CONTEXT* Context);

	nt_set_context_thread_t nt_set_context_thread = nullptr;
	nt_get_context_thread_t nt_get_context_thread = nullptr;
};