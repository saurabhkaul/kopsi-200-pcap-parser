Code Sample
Your task is to create a program, written in Rust, that will parse and print quote messages from a market data feed. When invoked with an -r flag, the program should re-order the messages according to the ‘quote accept time’ at the exchange. Take care to ensure it performs well (both in terms of wall time and memory usage), even when the input file is larger than available memory. The code should compile with with the latest stable rustc release.

Parsing the Market Data Feed
The relevant parts of the market data feed are sent via UDP broadcast to ports 15515/15516. For the purposes of this exercise, a standard pcap file is supplied which you will use to parse the UDP packets. Quote packets (specified below) begin with the ASCII bytes "B6034", and contain the five current best bids and asks on the market. Anything else should be ignored.

Your program should print the packet and quote accept times, the issue code, followed by the bids from 5th to 1st, then the asks from 1st to 5th; e.g.:

    $ ./parse-quote mdf-kospi200.20110216-0.pcap
    <pkt-time> <accept-time> <issue-code> <bqty5>@<bprice5> ... <bqty1>@<bprice1> <aqty1>@<aprice1> ... <aqty5>@<aprice5>
    ...
Reordering on Quote Accept Time
The delay between the exchange accepting the quote and us receiving the packet fluctuates for a variety of reasons; we may even receive the packets out of order. Given an optional flag -r, your program should output the messages ordered by the quote accept time.

You should assume that the difference between the quote accept time and the pcap packet time is never more than 3 seconds.

Test Data
A small sample file with a capture of the Kospi 200 market data feed from the first 30s of trading on 2011-02-16 can be downloaded here.

Quote Packet Specification
Item Name	Length	Remark
Data Type	2	B6
Information Type	2	03
Market Type	1	4
Issue code	12	ISIN code
Issue seq.-no.	3	
Market Status Type	2	
Total bid quote volume	7	
Best bid price(1st)	5	Decimals
Best bid quantity(1st)	7	Decimals
Best bid price(2nd)	5	
Best bid quantity(2nd)	7	
Best bid price(3rd)	5	
Best bid quantity(3rd)	7	
Best bid price(4th)	5	
Best bid quantity(4th)	7	
Best bid price(5th)	5	
Best bid quantity(5th)	7	
Total ask quote volume	7	
Best ask price(1st)	5	
Best ask quantity(1st)	7	
Best ask price(2nd)	5	
Best ask quantity(2nd)	7	
Best ask price(3rd)	5	
Best ask quantity(3rd)	7	
Best ask price(4th)	5	
Best ask quantity(4th)	7	
Best ask price(5th)	5	
Best ask quantity(5th)	7	
No. of best bid valid quote(total)	5	
No. of best bid quote(1st)	4	
No. of best bid quote(2nd)	4	
No. of best bid quote(3rd)	4	
No. of best bid quote(4th)	4	
No. of best bid quote(5th)	4	
No. of best ask valid quote(total)	5	
No. of best ask quote(1st)	4	
No. of best ask quote(2nd)	4	
No. of best ask quote(3rd)	4	
No. of best ask quote(4th)	4	
No. of best ask quote(5th)	4	
Quote accept time	8	HHMMSSuu
End of Message	1	0xff