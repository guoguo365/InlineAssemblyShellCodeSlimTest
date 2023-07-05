/*
异常：编辑器=》高级=》数据执行保护=》否
*/
#include <windows.h>
#include <iostream>

void _declspec(naked) ShellCode()
{
	__asm
	{
		/*
		将字符串转成ascii
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
		// push 0xbbafdf85   不需要

		// LoadLibraryA 0C 91 74 32
		push 0x0C917432

		mov ecx, esp
		push ecx            // 字符串首地址
		call fun_Payload

		popad
		retn

		// 2. 获取模块基址
		fun_GetModule :
			push ebp
			mov ebp, esp
			sub esp, 0xC
			push esi

			mov esi, dword ptr fs : [0x30]  // PEB指针
			mov esi, [esi + 0xC]            // LDR机构提地址
			mov esi, [esi + 0x1C]           // list
			mov esi, [esi]                  // list的第二项 kernel32
			mov esi, [esi + 0x8]            // kernel32.dll base
			mov eax, esi

			pop esi
			mov esp, ebp
			pop ebp
			retn

			/*
			获取进程地址
			@param dllBase   模块基址
			@param funName   函数名
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
			mov esi, [esi + 0x78]  // 导出表RVA
			lea esi, [edx + esi]   // 导出表VA

			mov edi, [esi + 0x1C]  // EAT RVA
			lea edi, [edx + edi]   // EAT VA
			mov[ebp - 0x4], edi    // EAT VA 放入局部变量中

			mov edi, [esi + 0x20]  // ENT RVA
			lea edi, [edx + edi]   // ENT VA
			mov[ebp - 0x8], edi    // ENT VA 放入局部变量中

			mov edi, [esi + 0x24]  // EOT RVA
			lea edi, [edx + edi]   // EOT VA
			mov[ebp - 0xC], edi    // EOT VA 放入局部变量中

			// 比较字符串 获取API
			xor ebx, ebx           // EAX清零，EAX作为索引
			cld
			jmp tag_cmpFirst       // 第一次执行eax只能为0
			tag_cmpLoop :
		inc ebx
			tag_cmpFirst :
		mov esi, [ebp - 0x8]     // 取出ENT
			mov esi, [esi + ebx * 4] // RVA
			mov edx, [ebp + 0x8]     // dllBase
			lea esi, [edx + esi]     // 函数名称字符串
			mov edi, [ebp + 0xC]     // 取funName传参，要查找的函数名
			mov edi, [edi]

			// 对函数名进行加密
			push esi
			call fun_GetHashCode
			//push eax
			//mov esi, esp
			//pop eax

			// 循环前，标志位要清零
			cmp edi, eax              // edi和eax中的值进行比较
			//repe cmpsb              // edi和eax中的地址的值进行比较
			jne tag_cmpLoop           // 不相等跳到循环开始处

			// 找到函数名
			mov esi, [ebp - 0xC]     // EOT
			xor edi, edi             // 为了不影响结果清空edi
			mov di, [esi + ebx * 2]  // 找到EAT表索引 eot是word类型，所以乘以2
			mov esi, [ebp - 0x4]     // 取出EAT地址
			mov esi, [esi + edi * 4] // 函数地址RVA
			mov edx, [ebp + 0x8]     // 取出dllBase
			lea eax, [edx + esi]     // 函数地址

			pop ecx
			pop ebx
			pop edx
			pop edi
			pop esi
			mov esp, ebp
			pop ebp
			retn 0xC

			/*
			接收一个参数
			@param 字符串首地址
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

			// 1. 先拿到dllBase
			call fun_GetModule
			mov[ebp - 0x4], eax           // dllBase存到ebp-4中

			// 2. 获取LoadLibraryA
			lea ecx, [ebp + 0xC]          // 获取字符串首地址
			push ecx                      // 要查找的函数名
			push eax                      // dllbBase
			call fun_GetProcAddress
			mov[ebp - 0x8], eax          // LoadLibrary地址

			// 3. 获取GetProcAddress    在调试过程中，发现不需要这个，用自己写的fun_GetProcAddress
			//lea ecx, [ebp + 0xC + 0x4]
			//push ecx
			//push [ebp - 0x4]
			//call fun_GetProcAddress
			//mov [ebp - 0xC], eax           // 存放GetProcAdress地址

			// 4. 调用LoadLibraryA 加载user32.dll
			lea ecx, [ebp + 0xC + 0x4]          // user32.dll字符串地址
			push ecx
			call[ebp - 0x8]                // 调用 LoadLibraryA 获取user32.dll
			mov[ebp - 0x10], eax          // 返回结果(user32 base)存放到ebp - 0x10

			// 5. 调用GetProcaddress，获取MessageBoxA地址
			lea ecx, [ebp + 0xC + 0x4 + 0xB]         // MessageBoxA字符串地址
			push ecx
			push[ebp - 0x10]
			call fun_GetProcAddress
			mov[ebp - 0x14], eax          // 返回结果(MessageBoxA的地址)放到ebp - 0x14

			// 6. 输出 I Love You
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
			获取hashcode值
			@para 要编码的字符串
			*/
		fun_GetHashCode:
			push ebp
			mov ebp, esp
			sub esp, 0x4
			push ecx
			push edx
			push ebx

			mov dword ptr[ebp - 0x4], 0  // DWORD digest = 0

			mov esi, [ebp + 0x8]          // 取参数strName
			xor ecx, ecx

			tag_hash_loop :
		mov ebx, [ebp - 0x4]
			shl ebx, 0x19				  // digest << 25
			mov edx, [ebp - 0x4]
			shr edx, 0x7                  // digest >> 7
			or ebx, edx					  // |
			xor eax, eax
			mov al, byte ptr[esi + ecx]           // strName是一个字节，所以要放在al中
			test al, al                   // al是否未0
			jz tag_hash_loop_end
			add ebx, eax				  // digest + *strName
			mov[ebp - 0x4], ebx           // 保存结果
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