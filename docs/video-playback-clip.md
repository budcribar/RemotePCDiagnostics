# Video playback test clip

`src/RemotePCDiagnostics.Host/Media/playback-test-1080p30.mp4` is the clip the video playback test (`VideoPlayback`) plays in a loop. It is
8 seconds of 1920x1080 30 fps H.264 (High profile, level 4.1, 3 Mbit/s, B-frames, a keyframe every 2 s) with 48 kHz stereo AAC audio, about
3 MB. It contains only ffmpeg's own generated test pattern and tone, so it carries no third-party content. It was made with:

```
ffmpeg -f lavfi -i "testsrc2=size=1920x1080:rate=30,noise=alls=6:allf=t" \
       -f lavfi -i "sine=frequency=440:sample_rate=48000,aformat=channel_layouts=stereo" \
       -t 8 -c:v libx264 -profile:v high -level 4.1 -pix_fmt yuv420p -preset medium -b:v 3M -maxrate 4M -bufsize 6M -g 60 -bf 2 \
       -c:a aac -b:a 96k -movflags +faststart playback-test-1080p30.mp4
```

The moving noise keeps every frame changing, so the decoder does real work on each one. H.264 is used because every graphics chip
Windows supports decodes it in hardware; if the clip changes, update `MediaFoundationVideoSource.Clip` (codec, size, rate, length).
