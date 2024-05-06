$password = ""

for ($i = 0; $i -lt 10000; $i++) {
    $password += "elephants_gently_trumpeting_in_the_wilderness_remind_us_of_the_beauty_o_nature_and_the_importance_" + "$i
"
}

$password = $password.Substring(0, (1000000 - 2))

# Output the random password to a file
$path = "C:\temp\bf.txt"
New-Item -ItemType File -Path $path -Force
Set-Content -Path $path -Value $password