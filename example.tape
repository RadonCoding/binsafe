Output example.gif
Set FontSize 8
Set Width 1200
Set Theme "Dracula"

Type "r2 -e log.quiet=true example.exe"
Enter
Type "eco zenburn"
Enter
Type "aa"
Enter
Sleep 5s
Type "s section..binsafe"
Enter
Type "pdui add byte [rax], al~:0..-1"
Enter

Type "q"
Enter

Type "r2 -e log.quiet=true example.protected.exe"
Enter
Type "eco zenburn"
Enter
Type "aa"
Enter
Sleep 5s
Type "s section..binsafe"
Enter
Type "pdui add byte [rax], al~:0..-1"
Enter
Sleep 5s