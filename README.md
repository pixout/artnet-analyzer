# Art-Net DMX traffic Analyzer
Utility for measuring ArtNet protocol traffic frame by frame.

What sort of data it outputs:
* Time code in (ns)
* ArtNet OpCode (ArtDMX, ArtPoll and so)
* Delay (between frames)
* Total time in (ms). Summed all delays 
* Total time in (ns). Summed all delays
* Universe (only for ArtDMX frames) in format: Net, SubNet, Physical
* ArtNet Sequence (only for ArtDMX frames)
* CRC32A hash for the frame (including header and data)

## Build

```cmd
go build
```

## Usage

```
Usage of artnet-analyzer.exe: 
  -filter-only-artdmx - Ignore all frames except ArtDMX     
  -listen-from-ip IP - Listen from specified IP. (default from all)
  -output FILENAME - Output file for results (default "output.tsv") 
  -port NUMBER - ArtNet Port (default 6454)
  -universes NUMBER - Frames Per Universes. How many universes are used?    
```
Example, Listen only ArtDMX frames from IP 2.0.0.111 and store in pixout.tsv file
```
artnet-analyzer -filter-only-artdmx -listen-from-ip 2.0.0.111 -output pixout.tsv
```

## Output TSV format

| Frame Num # | Time Code | ArtNet Operator | Delay | Total time in ms | Total time in ns | Universe | ArtNet Sequence | CRC32A |
|--- | :-------------: | ---- |----|----|----|----|----|----
| 0000000000 | 1638375163914667700 | DMX | 000000000s | 000000000s | 000000000s | 000	000	000 | 000 | c1bae682
| 0000000001 | 1638375163943667700 | DMX | 00000029ms | 000000000s | 000000000s | 000	001	000 | 000 | 8c9f5a16
| 0000000002 | 1638375163974632300 | DMX | 030.9646ms | 00000029ms | 00000029ms | 000	002	000 | 000 | eced5faf



## References

* [CRC32A](https://github.com/boguslaw-wojcik/crc32a) by Boguslaw Wojcik 
* [go-artnet](https://github.com/jsimonetti/go-artnet) by Jeroen Simonetti

# Author

**Pixout Company**

## License

Released under the [MIT License](https://github.com/jinzhu/copier/blob/master/License).
