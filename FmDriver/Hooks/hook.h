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
EXTERN_C ULONG_PTR halCounterQueryRoutine;								// ���� 1 ʱ��hook ֮ǰ�ĺ���
EXTERN_C void keQueryPerformanceCounterHook(ULONG_PTR* pStack);			// ���� 1 ʱ��hook �������������ݵ���ջ


