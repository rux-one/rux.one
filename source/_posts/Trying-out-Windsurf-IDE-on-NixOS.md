---
title: Trying out Windsurf IDE on NixOS ❄️
date: 2024-11-30 20:27:29
tags:
---

NixOS is currently my daily driver, but as of today I do not feel too confident about creating my own packages. I want to test Windsurf IDE so I decided to install it semi-correctly in terms of the nix philosophy. There does not seem to be a ready-made package yet.

What I did was:
- [downloaded](https://codeium.com/windsurf/download_linux) the Windsurf binary and extracted to my ~ directory.
- created a desktop entry using `home-manager`
```nix home.nix - partial
{
    (...) # rest of the file

    ".local/share/applications/windsurf.desktop".text = ''
      [Desktop Entry]
      Type=Application
      Name=Windsurf
      Comment=VsCode based IDE
      Icon=/home/bart/Windsurf/resources/app/resources/linux/code.png
      Exec=/home/bart/Windsurf/windsurf
      Terminal=false
      Categories=Tools;Programming
    '';
}
```

- added binary to the `PATH` variable

```nix home.nix - partial
{
    (...) # rest of the file

	home.file = {
	 ".bashrc".text = ''
	  (...) # other .BASHRC stuff
	     
	  export PATH=/home/bart/Windsurf/bin:$PATH
	'';
}
```

This way the only step I need to do on a fresh OS is to download the binary, everything else rebuilds automatically with `nixos-rebuild`.

Once I understand the nix packaging more I might try to do it properly, but I imagine by then it will appear in the package repository thanks to people smarter than me. 🤓