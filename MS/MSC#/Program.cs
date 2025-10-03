using System;
using System.Collections.Generic;

class Program
{
    static void PlusMinus(List<int> arr)
    {
        int n = arr.Count;
        int pos = 0, neg = 0, zero = 0;
        
        foreach (var x in arr)
        {
            if (x > 0) pos++;
            else if (x < 0) neg++;
            else zero++;
        }

        Console.WriteLine($"{(double)pos / n:F6}");
        Console.WriteLine($"{(double)neg / n:F6}");
        Console.WriteLine($"{(double)zero / n:F6}");
    }
    static void Main()
    {
        // Lectura de datos como en HackerRank
        int n = int.Parse(Console.ReadLine());
        var arr = new List<int>(Array.ConvertAll(Console.ReadLine().Split(' '), int.Parse));

        PlusMinus(arr);
    }
}
