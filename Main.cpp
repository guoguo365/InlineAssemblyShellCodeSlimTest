/*
�쳣���༭��=���߼�=������ִ�б���=����
*/
#include <windows.h>
#include <iostream>

void _declspec(naked) ShellCode()
{
	__asm
	{
		/*
		���ַ���ת��ascii
		LoadLibraryA    0C 91 74 32
		GetProcAddress  BB AF DF 85
		user32.dll      75 73 65 72  33 32 2E 64  6C 6C 00
		MessageBoxA     1E 38 0A 6A
		I Love You      49 20 4C 6F  76 65 20 59  6F 75 00
		*/
		pushad
		sub esp, 0x30

		// I Love You 49 20 4C 6F  76 65 20 59  6F 75 00
		mov byte ptr ds : [esp - 1] , 0x0
		sub esp, 0x1
		push 0x756F
		push 0x59206576
		push 0x6F4C2049

		// MessageBoxA
		push 0x1E380A6A

		// user32.dll
		mov byte ptr ds : [esp - 1] , 0x0
		sub esp, 0x1
		mov ax, 0x6C6C
		mov word ptr ds : [esp - 2] , ax
		sub esp, 0x2
		push 0x642E3233
		push 0x72657375

		// GetProAddress
		// push 0xbbafdf85   ����Ҫ

		// LoadLibraryA 0C 91 74 32
		push 0x0C917432

		mov ecx, esp
		push ecx            // �ַ����׵�ַ
		call fun_Payload

		popad
		retn

		// 2. ��ȡģ���ַ
		fun_GetModule :
			push ebp
			mov ebp, esp
			sub esp, 0xC
			push esi

			mov esi, dword ptr fs : [0x30]  // PEBָ��
			mov esi, [esi + 0xC]            // LDR�������ַ
			mov esi, [esi + 0x1C]           // list
			mov esi, [esi]                  // list�ĵڶ��� kernel32
			mov esi, [esi + 0x8]            // kernel32.dll base
			mov eax, esi

			pop esi
			mov esp, ebp
			pop ebp
			retn

			/*
			��ȡ���̵�ַ
			@param dllBase   ģ���ַ
			@param funName   ������
			*/
		fun_GetProcAddress:
			push ebp
			mov ebp, esp
			sub esp, 0x10
			push esi
			push edi
			push edx
			push ebx
			push ecx

			mov edx, [ebp + 0x8]   // dllBase
			mov esi, [edx + 0x3C]  // lf_anew
			lea esi, [edx + esi]   // NT header
			mov esi, [esi + 0x78]  // ������RVA
			lea esi, [edx + esi]   // ������VA

			mov edi, [esi + 0x1C]  // EAT RVA
			lea edi, [edx + edi]   // EAT VA
			mov[ebp - 0x4], edi    // EAT VA ����ֲ�������

			mov edi, [esi + 0x20]  // ENT RVA
			lea edi, [edx + edi]   // ENT VA
			mov[ebp - 0x8], edi    // ENT VA ����ֲ�������

			mov edi, [esi + 0x24]  // EOT RVA
			lea edi, [edx + edi]   // EOT VA
			mov[ebp - 0xC], edi    // EOT VA ����ֲ�������

			// �Ƚ��ַ��� ��ȡAPI
			xor ebx, ebx           // EAX���㣬EAX��Ϊ����
			cld
			jmp tag_cmpFirst       // ��һ��ִ��eaxֻ��Ϊ0
			tag_cmpLoop :
		inc ebx
			tag_cmpFirst :
		mov esi, [ebp - 0x8]     // ȡ��ENT
			mov esi, [esi + ebx * 4] // RVA
			mov edx, [ebp + 0x8]     // dllBase
			lea esi, [edx + esi]     // ���������ַ���
			mov edi, [ebp + 0xC]     // ȡfunName���Σ�Ҫ���ҵĺ�����
			mov edi, [edi]

			// �Ժ��������м���
			push esi
			call fun_GetHashCode
			//push eax
			//mov esi, esp
			//pop eax

			// ѭ��ǰ����־λҪ����
			cmp edi, eax              // edi��eax�е�ֵ���бȽ�
			//repe cmpsb              // edi��eax�еĵ�ַ��ֵ���бȽ�
			jne tag_cmpLoop           // ���������ѭ����ʼ��

			// �ҵ�������
			mov esi, [ebp - 0xC]     // EOT
			xor edi, edi             // Ϊ�˲�Ӱ�������edi
			mov di, [esi + ebx * 2]  // �ҵ�EAT������ eot��word���ͣ����Գ���2
			mov esi, [ebp - 0x4]     // ȡ��EAT��ַ
			mov esi, [esi + edi * 4] // ������ַRVA
			mov edx, [ebp + 0x8]     // ȡ��dllBase
			lea eax, [edx + esi]     // ������ַ

			pop ecx
			pop ebx
			pop edx
			pop edi
			pop esi
			mov esp, ebp
			pop ebp
			retn 0xC

			/*
			����һ������
			@param �ַ����׵�ַ
			*/
		fun_Payload:
			push ebp
			mov ebp, esp
			sub esp, 0x20
			push esi
			push edi
			push edx
			push ebx
			push ecx

			// 1. ���õ�dllBase
			call fun_GetModule
			mov[ebp - 0x4], eax           // dllBase�浽ebp-4��

			// 2. ��ȡLoadLibraryA
			lea ecx, [ebp + 0xC]          // ��ȡ�ַ����׵�ַ
			push ecx                      // Ҫ���ҵĺ�����
			push eax                      // dllbBase
			call fun_GetProcAddress
			mov[ebp - 0x8], eax          // LoadLibrary��ַ

			// 3. ��ȡGetProcAddress    �ڵ��Թ����У����ֲ���Ҫ��������Լ�д��fun_GetProcAddress
			//lea ecx, [ebp + 0xC + 0x4]
			//push ecx
			//push [ebp - 0x4]
			//call fun_GetProcAddress
			//mov [ebp - 0xC], eax           // ���GetProcAdress��ַ

			// 4. ����LoadLibraryA ����user32.dll
			lea ecx, [ebp + 0xC + 0x4]          // user32.dll�ַ�����ַ
			push ecx
			call[ebp - 0x8]                // ���� LoadLibraryA ��ȡuser32.dll
			mov[ebp - 0x10], eax          // ���ؽ��(user32 base)��ŵ�ebp - 0x10

			// 5. ����GetProcaddress����ȡMessageBoxA��ַ
			lea ecx, [ebp + 0xC + 0x4 + 0xB]         // MessageBoxA�ַ�����ַ
			push ecx
			push[ebp - 0x10]
			call fun_GetProcAddress
			mov[ebp - 0x14], eax          // ���ؽ��(MessageBoxA�ĵ�ַ)�ŵ�ebp - 0x14

			// 6. ��� I Love You
			push 0
			push 0
			lea ecx, [ebp + 0xC + 0x4 + 0xB + 0x4]
			push ecx
			push 0
			call[ebp - 0x14]

			pop ecx
			pop ebx
			pop edx
			pop edi
			pop esi
			mov esp, ebp
			pop ebp
			retn 0x4

			/*
			��ȡhashcodeֵ
			@para Ҫ������ַ���
			*/
		fun_GetHashCode:
			push ebp
			mov ebp, esp
			sub esp, 0x4
			push ecx
			push edx
			push ebx

			mov dword ptr[ebp - 0x4], 0  // DWORD digest = 0

			mov esi, [ebp + 0x8]          // ȡ����strName
			xor ecx, ecx

			tag_hash_loop :
		mov ebx, [ebp - 0x4]
			shl ebx, 0x19				  // digest << 25
			mov edx, [ebp - 0x4]
			shr edx, 0x7                  // digest >> 7
			or ebx, edx					  // |
			xor eax, eax
			mov al, byte ptr[esi + ecx]           // strName��һ���ֽڣ�����Ҫ����al��
			test al, al                   // al�Ƿ�δ0
			jz tag_hash_loop_end
			add ebx, eax				  // digest + *strName
			mov[ebp - 0x4], ebx           // ������
			inc ecx                       // strName++
			jmp tag_hash_loop
			tag_hash_loop_end :
		mov eax, [ebp - 0x4]

			pop ebx
			pop edx
			pop ecx
			mov esp, ebp
			pop ebp
			retn 0x4
	}
}

int main()
{
	ShellCode();
	return 0;
}