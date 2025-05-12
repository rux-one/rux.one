---
title: Hello PineTime!
date: 2024-12-29 15:07
tags:
---

It's been months since I ordered myself a smartwatch made by Pine64. 
I was slowly testing available firmwares, learning about the hardware, but never really made any progress on customizing it beyond replacing the factory strap with a generic magnetic one. 

![Magnetic strap for pinetime](/images/custom-pinetime-strap.jpg "Pinetime magnetic strap")

InfiniTime has quickly become my daily firmware but I could see room for improvement, specifically for my type of activities. My first idea was to create a [Pomodor Timer](https://en.wikipedia.org/wiki/Pomodoro_Technique "Pomodoro") for my PineTime.

Today I finally managed to understand how the apps are built into the firmware and made the following progress:
- added new app to the apps list
- added a new fontawesome glyph to the build
- how to build & run [InfiniSim](https://github.com/InfiniTimeOrg/InfiniSim "InfiniTime Simulator")

{% html5video auto 500px %} /videos/hello-pinetime.mp4 {% endhtml5video %}

Next I will be trying to understand how to actually measure time in the new app.