```bash
# Your code here!
f
echo "XXXXXXXX"

# Basic Print
face="123"
echo $face

# Truthiness Test
bTest=true

if [[ "$bTest" == true ]]; then
    echo "True"
fi

# Is Set Test
## don't set > notEmpty="abc"

var="/path/to/some/file.txt"

if [[ ! -e $var ]]; then
  echo "The file $var does not exist."
else
  echo "The file $var exists."
fi

# Dir path is set:

if [[ ! -e $var ]]; then

# String check : Check whether a variable $var is empty or has a length of zero.
var=""

if [[ -z $var ]]; then
  echo "The variable is empty or has no value."
else
  echo "The variable has a value: $var"
fi
```

