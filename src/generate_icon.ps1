Add-Type -AssemblyName System.Drawing

function New-RoundedPath([float]$X, [float]$Y, [float]$Width, [float]$Height, [float]$Radius) {
    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $diameter = $Radius * 2
    $path.AddArc($X, $Y, $diameter, $diameter, 180, 90)
    $path.AddArc($X + $Width - $diameter, $Y, $diameter, $diameter, 270, 90)
    $path.AddArc($X + $Width - $diameter, $Y + $Height - $diameter, $diameter, $diameter, 0, 90)
    $path.AddArc($X, $Y + $Height - $diameter, $diameter, $diameter, 90, 90)
    $path.CloseFigure()
    return $path
}

function New-IconFrame([int]$Size) {
    $bitmap = [System.Drawing.Bitmap]::new($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $graphics.ScaleTransform($Size / 32.0, $Size / 32.0)

    $shell = New-RoundedPath 2 2 28 21 3
    $shellBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 30, 49, 65))
    $shellPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 111, 143, 159), 1)
    $graphics.FillPath($shellBrush, $shell)
    $graphics.DrawPath($shellPen, $shell)

    $screen = New-RoundedPath 5 5 22 13 1.5
    $screenBrush = [System.Drawing.Drawing2D.LinearGradientBrush]::new(
        [System.Drawing.RectangleF]::new(5, 5, 22, 13),
        [System.Drawing.Color]::FromArgb(255, 20, 98, 139),
        [System.Drawing.Color]::FromArgb(255, 43, 157, 181),
        [System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
    $graphics.FillPath($screenBrush, $screen)

    $crossPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 240, 249, 250), 2.1)
    $crossPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $crossPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $graphics.DrawLine($crossPen, 10, 8, 17, 15)
    $graphics.DrawLine($crossPen, 17, 8, 10, 15)

    $standBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 108, 130, 143))
    $graphics.FillRectangle($standBrush, 14, 23, 4, 3)
    $base = New-RoundedPath 9 26 14 2.5 1
    $graphics.FillPath($standBrush, $base)

    $handlePen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 245, 179, 75), 3)
    $handlePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $handlePen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $graphics.DrawLine($handlePen, 24, 20, 29, 26)
    $lensBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(235, 30, 75, 92))
    $lensPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 255, 198, 105), 2)
    $graphics.FillEllipse($lensBrush, 18.5, 13.5, 11, 11)
    $graphics.DrawEllipse($lensPen, 18.5, 13.5, 11, 11)
    $lensGlint = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(220, 211, 246, 246), 1.2)
    $graphics.DrawLine($lensGlint, 21, 17, 23, 15.5)

    $stream = [System.IO.MemoryStream]::new()
    $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    $png = $stream.ToArray()
    $stream.Dispose()
    $graphics.Dispose()
    $bitmap.Dispose()
    $shell.Dispose(); $shellBrush.Dispose(); $shellPen.Dispose()
    $screen.Dispose(); $screenBrush.Dispose(); $crossPen.Dispose()
    $standBrush.Dispose(); $base.Dispose(); $handlePen.Dispose()
    $lensBrush.Dispose(); $lensPen.Dispose(); $lensGlint.Dispose()
    return ,$png
}

$sizes = @(16, 32, 48)
$frames = [System.Collections.Generic.List[byte[]]]::new()
foreach ($size in $sizes) { $frames.Add((New-IconFrame $size)) }

$output = [System.IO.MemoryStream]::new()
$writer = [System.IO.BinaryWriter]::new($output)
$writer.Write([UInt16]0)
$writer.Write([UInt16]1)
$writer.Write([UInt16]$frames.Count)
$offset = 6 + (16 * $frames.Count)
for ($i = 0; $i -lt $frames.Count; $i++) {
    $edge = if ($sizes[$i] -eq 256) { 0 } else { $sizes[$i] }
    $writer.Write([byte]$edge)
    $writer.Write([byte]$edge)
    $writer.Write([byte]0)
    $writer.Write([byte]0)
    $writer.Write([UInt16]1)
    $writer.Write([UInt16]32)
    $writer.Write([UInt32]$frames[$i].Length)
    $writer.Write([UInt32]$offset)
    $offset += $frames[$i].Length
}
foreach ($frame in $frames) { $writer.Write($frame) }
$writer.Flush()
[System.IO.File]::WriteAllBytes((Join-Path $PSScriptRoot '..\app.ico'), $output.ToArray())
$writer.Dispose()
$output.Dispose()