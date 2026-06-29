Output example.gif
Set FontSize 10
Set Width 1200
Set Theme "Dracula"

Type "r2 notepad.exe"
Enter
Type "aa"
Enter
Type "pdb @ sym.main"
Enter

Type "q"
Enter

Type "r2 notepad.protected.exe"
Enter
Type "aa"
Enter
Type "pdb @ sym.main"
Enter
Type "s 0x140007132"
Enter
Type "s `aoj~jump[1]`"
Enter
Type "pd 10"
Enter
Sleep 5s