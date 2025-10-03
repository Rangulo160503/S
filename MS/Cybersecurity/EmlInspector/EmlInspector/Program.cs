using System.Text.Json;
using System.Text.Json.Serialization;
using MimeKit;

record EmlAttachment(
    string FileName,
    string ContentType,
    long? SizeBytes,
    string SavedPath);

record EmlInfo(
    string? Subject,
    string? From,
    string[] To,
    string[] Cc,
    string[] Bcc,
    DateTimeOffset? Date,
    string? MessageId,
    string? ReturnPath,
    string? DkimSignature,
    string? SpfResult,
    string TextBody,
    string HtmlBody,
    EmlAttachment[] Attachments,
    string SourcePath
);

class Program
{
    static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Uso: EmlInspector <ruta.eml | carpeta> [--out <carpeta_adjuntos>]");
            return 1;
        }

        string target = args[0];
        string outDir = GetArg(args, "--out") ?? "attachments";

        var files = System.IO.File.Exists(target)
            ? new[] { target }
            : System.IO.Directory.GetFiles(target, "*.eml", SearchOption.AllDirectories);

        System.IO.Directory.CreateDirectory(outDir);

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        foreach (var file in files)
        {
            try
            {
                var info = ParseEml(file, outDir);
                Console.WriteLine(JsonSerializer.Serialize(info, options));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ERROR] {file}: {ex.Message}");
            }
        }

        return 0;
    }

    static string? GetArg(string[] args, string name)
    {
        var idx = Array.IndexOf(args, name);
        return (idx >= 0 && idx + 1 < args.Length) ? args[idx + 1] : null;
    }

    static EmlInfo ParseEml(string path, string outDir)
    {
        using var stream = System.IO.File.OpenRead(path);
        var msg = MimeMessage.Load(stream);

        var textBody = msg.TextBody ?? string.Empty;
        var htmlBody = msg.HtmlBody ?? string.Empty;

        var attachments = new List<EmlAttachment>();
        foreach (var part in msg.BodyParts)
        {
            if (part is MimePart mp && mp.IsAttachment)
            {
                var fileName = mp.FileName ?? "adjunto.bin";
                var safeName = MakeSafeFileName(fileName);
                var savePath = System.IO.Path.Combine(outDir, safeName);

                using var fs = System.IO.File.Create(savePath);
                mp.Content.DecodeTo(fs);

                attachments.Add(new EmlAttachment(
                    FileName: fileName,
                    ContentType: mp.ContentType?.MimeType ?? "application/octet-stream",
                    SizeBytes: fs.Length,
                    SavedPath: savePath
                ));
            }
        }

        string? header(string h) => msg.Headers.Contains(h) ? msg.Headers[h] : null;

        return new EmlInfo(
            Subject: msg.Subject,
            From: string.Join(", ", msg.From.Select(a => a.ToString())),
            To: msg.To.Select(a => a.ToString()).ToArray(),
            Cc: msg.Cc.Select(a => a.ToString()).ToArray(),
            Bcc: msg.Bcc.Select(a => a.ToString()).ToArray(),
            Date: msg.Date,
            MessageId: msg.MessageId,
            ReturnPath: header("Return-Path"),
            DkimSignature: header("DKIM-Signature"),
            SpfResult: header("Received-SPF"),
            TextBody: textBody,
            HtmlBody: htmlBody,
            Attachments: attachments.ToArray(),
            SourcePath: path
        );
    }

    static string MakeSafeFileName(string name)
    {
        foreach (var c in System.IO.Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name;
    }
}