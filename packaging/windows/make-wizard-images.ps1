<#
.SYNOPSIS
    Draws the Windows installer's wizard images from the Echoes logo (packaging/windows/Echoes.iss shows them).

.DESCRIPTION
    One PNG for every DPI scale Inno Setup sizes its image areas for (100 % to 250 %), so no scale stretches or blurs
    an image. The ground is transparent: the panel and page colors (light and dark) come from Echoes.iss.
      wizard-<w>x<h>.png   the left panel of the Finished page: the logo a little above the middle
      small-<n>.png        the logo in the top-right corner of the other pages
    Runs in Windows PowerShell 5.1 and PowerShell 7 (System.Drawing). Keep this file ASCII: 5.1 reads it as ANSI.

.EXAMPLE
    .\make-wizard-images.ps1 -OutDir $env:TEMP\echoes-wizard-images
#>
param(
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string]$Logo   # default: Assets/logo.png of this repository
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
# set here, not as the param default: Windows PowerShell 5.1 has no $PSScriptRoot yet while it binds parameters
if (-not $Logo) { $Logo = Join-Path $PSScriptRoot '..\..\Assets\logo.png' }

# The image areas of Inno Setup 6.7 at 100, 125, 150, 175, 200, 225 and 250 % (WizardImageFile and
# WizardSmallImageFile help topics), with the default font and WizardSizePercent.
$panels = @(@(202, 386), @(269, 515), @(336, 643), @(403, 772), @(430, 824), @(498, 953), @(534, 1022))
$smalls = @(58, 77, 97, 116, 124, 143, 159)

$LogoShare = 0.62     # of the panel's width
$LogoCenter = 0.44    # of the panel's height, where the logo's middle sits (optically centered)

function Save-Png([int]$Width, [int]$Height, [System.Drawing.RectangleF]$Target, [string]$Path) {
    $bmp = New-Object System.Drawing.Bitmap($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        try {
            $g.Clear([System.Drawing.Color]::Transparent)
            $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
            $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            # mirrored edges: no faint frame from the pixels outside the source when it is scaled down
            $attributes = New-Object System.Drawing.Imaging.ImageAttributes
            $attributes.SetWrapMode([System.Drawing.Drawing2D.WrapMode]::TileFlipXY)
            $g.DrawImage($script:source, [System.Drawing.Rectangle]::Round($Target), 0, 0, $script:source.Width,
                         $script:source.Height, [System.Drawing.GraphicsUnit]::Pixel, $attributes)
            $attributes.Dispose()
        }
        finally { $g.Dispose() }
        $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    finally { $bmp.Dispose() }
}

$Logo = (Resolve-Path -LiteralPath $Logo).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
$source = [System.Drawing.Image]::FromFile($Logo)
try {
    $aspect = $source.Height / $source.Width

    foreach ($p in $panels) {
        $w = $p[0]; $h = $p[1]
        $lw = [math]::Round($w * $LogoShare); $lh = [math]::Round($lw * $aspect)
        $target = New-Object System.Drawing.RectangleF((($w - $lw) / 2), ($h * $LogoCenter - $lh / 2), $lw, $lh)
        Save-Png $w $h $target (Join-Path $OutDir "wizard-${w}x${h}.png")
    }

    foreach ($n in $smalls) {
        $lh = $n; $lw = [math]::Round($n / $aspect)
        $target = New-Object System.Drawing.RectangleF((($n - $lw) / 2), 0, $lw, $lh)
        Save-Png $n $n $target (Join-Path $OutDir "small-$n.png")
    }
}
finally { $source.Dispose() }

$made = @(Get-ChildItem -LiteralPath $OutDir -Filter *.png)
"Wizard images: $($made.Count) files, $([math]::Round(($made | Measure-Object Length -Sum).Sum / 1KB)) KB in $OutDir"
