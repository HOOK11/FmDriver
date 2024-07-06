#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void(__fastcall* INFINITYHOOKCALLBACK)(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction);

BOOLEAN start();

EXTERN_C BOOLEAN IfhInitialize2(INFINITYHOOKCALLBACK fptr);

BOOLEAN IfhRelease2();

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

	
#ifdef __cplusplus
	}
#endif

EXTERN_C void checkLogger();
EXTERN_C ULONG_PTR halCounterQueryRoutine;								// 等于 1 时，hook 之前的函数
EXTERN_C void keQueryPerformanceCounterHook(ULONG_PTR* pStack);			// 等于 1 时，hook 函数中用来回溯调用栈


