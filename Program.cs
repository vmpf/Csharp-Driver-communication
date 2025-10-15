using System;

class Program
{
    static void Main(string[] args)
    {
        DriverCommunication driver = new DriverCommunication();

        if (driver.FindDriver())
        {
            Console.WriteLine("Driver handle opened successfully.");

            int pid = driver.FindProcess("notepad.exe");
            if (pid != 0)
            {
                Console.WriteLine($"Found notepad.exe with PID: {pid}");

                ulong imageBase = driver.FindImage();
                Console.WriteLine($"Image base address: 0x{imageBase:X}");

                ulong guardedRegion = driver.GetGuardedRegion();
                Console.WriteLine($"Guarded region address: 0x{guardedRegion:X}");
            }
            else
            {
                Console.WriteLine("Could not find notepad.exe process.");
            }

            driver.CloseDriver();
            Console.WriteLine("Driver handle closed.");
        }
        else
        {
            Console.WriteLine("Failed to open driver handle. Check if the driver is loaded and the path is correct.");
        }

        Console.ReadKey();
    }
}
