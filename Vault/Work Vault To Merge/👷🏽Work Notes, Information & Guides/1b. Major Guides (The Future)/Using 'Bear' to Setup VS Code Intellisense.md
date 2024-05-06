# The Bear
```
bear –config bear.conf --output private/msm-google/compile_commands.json -- build_kernel.sh

bear --config bear.config --output ~/work/devices/s21plus/SM-G996B_RR_Opensource/compile_commands.json -- build_kernel.sh

Compile commands Location:

	\\wsl$\Ubuntu-22.04\home\kt\work\devices\s21plus\SM-G996B_RR_Opensource\compile_commands.json

	~/work/devices/s21plus/SM-G996B_RR_Opensource/compile_commands.json

	\\wsl.localhost\Ubuntu-22.04\home

Sample Contents:

              {
                "compilation": {
                  "compilers_to_recognize": [
                    {
                      "executable": "prebuilts-master/clang/host/linux-x86/clang-r349610/bin/clang" ,
                      "additional_flags": []
                    }
                  ],
                  "compilers_to_exclude": []
                },
                "output": {
                  "content": {
                    "include_only_existing_source": true,
                    "paths_to_include": [],
                    "paths_to_exclude": []
                  },
                  "format": {
                    "command_as_array": true,
                    "drop_output_field": false
                  }
                }
              }


```

# Output JSON Stage Variables

`adb shell 'echo "get_str_var boot_stages" > /dev/deboot ; cat /dev/deboot ; echo'

