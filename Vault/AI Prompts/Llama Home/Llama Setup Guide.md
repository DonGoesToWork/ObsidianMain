# To Run:
```
A:
cd A:\text-generation-webui
conda activate textgen
python server.py --model LLaMA-7B --load-in-8bit
```

# Install Notes, Tips and Tricks
Reddit Llama Tutorial: https://www.reddit.com/r/MachineLearning/comments/11kwdu9/d_tutorial_run_llama_on_8gb_vram_on_windows/
Text Generation Web-UI: https://github.com/oobabooga/text-generation-webui
Int8 Guide: https://rentry.org/llama-tard-v2#bonus-3-convert-the-weights-yourself-optional-recommended

Cude Workarounds: https://github.com/DeXtmL/bitsandbytes-win-prebuilt
Final Link When Running: http://127.0.0.1:7860/

My "textgen" conda env:
`C:\Users\Destro\miniconda3\envs`

Paths to Projects:
`A:\llama`
`A:\text-generation-webui`

##  Other Notes

* Make sure to run "Anaconda Prompt" as administrator. Otherwise, pip install crap won't work.
* Sample main.py path: `C:\Users\Destro\miniconda3\Lib\site-packages\bitsandbytes\cuda_setup\main.py`

## Persistent Error:

```
Loading LLaMA-7B...
Warning: no GPU has been detected.
Falling back to CPU mode.
```

No known solution for now. Hopefully one appears in the future as the process is streamlined.

# Non-Error Version That Doesn't Work

I used the steps from the comment thread to run the install script, but that doesn't work. Just never advances past 0% when generating prompts.

Path: `A:\AI_Again`


Default File Contents for start-webui.bat:

```
@echo off

@echo Starting the web UI...

set INSTALL_ENV_DIR=%cd%\installer_files\env
set PATH=%INSTALL_ENV_DIR%;%INSTALL_ENV_DIR%\Library\bin;%INSTALL_ENV_DIR%\Scripts;%INSTALL_ENV_DIR%\Library\usr\bin;%PATH%
call conda activate
cd text-generation-webui
call python server.py --auto-devices --cai-chat

pause

```

Mine:

```

```


