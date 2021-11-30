# install dependencies
Install-Module oh-my-posh -Scope CurrentUser
Install-Module posh-git -Scope CurrentUser
Install-Module Terminal-Icons -Scope CurrentUser
Install-Module PSReadLine -AllowPrerelease

# download nerdfont (patched version)
# https://www.nerdfonts.com/
# https://github.com/ryanoasis/nerd-fonts/tree/master/patched-fonts/CascadiaCode/Regular/complete
# https://github.com/ryanoasis/nerd-fonts/raw/master/patched-fonts/Meslo/M-DZ/Regular/complete/
# LG - Line Gap
# L - Large
# M - Medium
# S - Small
# DZ - Dotted Zero
# SZ - Slashed Zero

mkdir %USERPROFILE%\Fonts
Invoke-WebRequest -Uri "https://github.com/ryanoasis/nerd-fonts/blob/master/patched-fonts/CascadiaCode/Regular/complete/Caskaydia%20Cove%20Regular%20Nerd%20Font%20Complete%20Mono%20Windows%20Compatible.otf?raw=true" -OutFile "%USERPROFILE%\Fonts/CascadiaCode.otf"

###########################
# Edit profile
###########################
$config = @'
$modules = "posh-git","oh-my-posh","Terminal-Icons"
$modules | ForEach-Object {
 Write-Host Importing $_;
 Import-Module $_
}

# Autocompletion for arrow keys
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
Set-PSReadlineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadlineKeyHandler -Key DownArrow -Function HistorySearchForward

Set-PoshPrompt  powerlevel10k_modern

# Set your Favorite Alias here 
Set-Alias -Name k -Value kubectl
'@
New-Item $profile
Set-Content $profile $config
