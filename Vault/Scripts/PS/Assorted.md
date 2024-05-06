# Password Generator

```powershell
$possibleChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_+"
$passwordLength = 12
$password = ""
$random = New-Object System.Random

for ($i = 0; $i -lt $passwordLength; $i++) {
    $randomChar = $possibleChars[$random.Next(0, $possibleChars.Length)]
    $password += $randomChar
}

Write-Output $password
```

# Find a Word In File in Directory and any sub-Directories Recursively

```powershell
# Prompt the developer to enter the string they want to search for
$searchString = "feaceacewacweacawecaweaceaffwecwcefewfwefwefwefwef"

# Specify the directory to start the search from
$startingDirectory = "C:\Users\Destro\Desktop\sd\stable-diffusion-webui"

# Recursively search for the string in all files within the starting directory
Get-ChildItem $startingDirectory -Recurse | Select-String -Pattern $searchString
```




