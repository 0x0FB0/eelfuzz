# [eelfuzz.py]

```
      ,--------(TCP/UDP)-----[radamsa]
      |                         ||
      |                         ||
      |               ,----------`
  [client]       [server]       |
      |              |          |
      |              |          |
  [eelfuzz]----------`          |
      |                         |    
      `------------------------`
```

Network fuzzing platform with automated packet capture and replay.
Based on fuzzmon and radamsa projects.

Requires tshark for packet dissection

``` sudo apt install tshark ```

Python requirements in requirements.txt
