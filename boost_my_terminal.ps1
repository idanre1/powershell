Install-Module oh-my-posh -Scope CurrentUser
Install-Module posh-git -Scope CurrentUser
Install-Module Terminal-Icons -Scope CurrentUser
Install-Module PSReadLine -AllowPrerelease

#download nerdfont
#https://www.nerdfonts.com/font-downloads
#https://github.com/ryanoasis/nerd-fonts/releases/download/v2.1.0/Meslo.zip
# msft fonts
#https://github.com/microsoft/cascadia-code/releases?WT.mc_id=-blog-scottha

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

