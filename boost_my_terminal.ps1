Install-Module oh-my-posh -Scope CurrentUser
Install-Module posh-git -Scope CurrentUser
Install-Module Terminal-Icons -Scope CurrentUser
Install-Module PSReadLine -AllowPrerelease

#download nerdfont (patched version)
#https://github.com/ryanoasis/nerd-fonts/raw/master/patched-fonts
https://github.com/ryanoasis/nerd-fonts/raw/master/patched-fonts/Meslo/M-DZ/Regular/complete/
# msft fonts
#https://github.com/microsoft/cascadia-code/releases?WT.mc_id=-blog-scottha
# LG - Line Gap
# L - Large
# M - Medium
# S - Small
# DZ - Dotted Zero
# SZ - Slashed Zero


echo $Profile
########################
$modules = "posh-git","oh-my-posh","Terminal-Icons"
$modules | ForEach-Object {
 Write-Host Importing $_;
 Import-Module $_
}

# # Autocompletion for arrow keys
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
Set-PSReadlineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadlineKeyHandler -Key DownArrow -Function HistorySearchForward

Set-PoshPrompt  powerlevel10k_modern

# Set your Favorite Alias here 
Set-Alias -Name k -Value kubectl
