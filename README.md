# Bloom Filter-Based Multicast for Information Centric Networks

This project contains an extended description, as well as the core parts of code that were used in my
Bachelor thesis, which was conducted in the context of the European project
[“Point: iP Over IcN – the betTer ip"](https://cordis.europa.eu/project/id/643990). 

For the people that are interested in experimenting with my prototype, 
contact me and I will send you a Linux-based virtual box with a preconfigured, set up environment.

## Context

This work is centered around creating a prototype system that facilitates multicast by taking advantage of the
bloom filter structure.

Our system utilizes the Publish-Subscribe architecture (pub-sub).
Users that wants to provide content are called publishers, and users that want to consume it are called
subscribers.

An example of where this work could be utilized is Web-based IPTV. 
In this context, chanel providers could register themselves as publishers, to deliver their broadcast
to the interested subscribers, who meet the requirements.

## The big picture

The ultimate goal of our system is to facilitate message transmission from publishers to all subscribers of a specific multicast group.
We achieve this behavior by doing the following:
We assign each network switch a unique 128 bit binary number.


## High Level Architecture

Our system contains the following entities:
* Randezvous 
