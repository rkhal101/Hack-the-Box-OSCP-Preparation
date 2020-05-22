# My OSCP Journey — A Review

![](https://cdn-images-1.medium.com/max/600/1*APP_5w2dQWwrFAexknX2Ug.png)

This post describes the journey that I went through while studying for the Offensive Security Certified Professional \(OSCP\) certification. It outlines my personal experience and therefore is very subjective. I don’t go into any details about the OSCP labs and exam due to restrictions set by Offensive Security. Instead, I’ve structured it in such a way that it gives the advice that I wish I had gotten when I first started the certification.

## When it all Began — Or so I thought…

I first enrolled in the OSCP certification at the beginning of last year. I had just finished a Master’s degree in Computer Science and started my first full time position as a Security Assessment Analyst. At the time, I had a background in web security, however, I recognized that there was a huge gap in my knowledge of the entire process of penetration testing. This is what peeked my interest in the OSCP certification. 

Without doing much research into the prerequisites of the certification, I enrolled in the PWK v1.1.6 course and made the incorrect assumption that it would be like any other course that I have taken where you get a book or manual that teaches you the foundational knowledge to tackle the labs and exam. And boy was I wrong!

For those of you that had done v1 of the course, you know that the course material does not at all go in depth on the techniques you need to compromise a host and escalate privileges. Therefore, although I completed most of the course manual at the time with the exercises, I felt completely lost when it came to the labs. I felt that there was such a huge gap between what was taught in the course material and what you encountered in the labs. That in combination with having just started a new job and just finished a Master’s degree, I didn’t realize how burnt out I already was. 

I let my lab time \(and exam attempt\) expire and decided to instead focus on my job. That is also when I decided to never go back to the OSCP labs until I felt that I’m not only prepared for the OSCP labs but also for the exam.

So here’s advice \#1.

> I would not recommend enrolling into the OSCP course unless you have previous experience in all the general steps that you take to compromise a host: Recon, initial foothold and privilege escalation. This can be experience that you’ve gotten through work or through self study using platforms such as Hack the Box \(HTB\).

## Pre-Preparation — TJ\_Null’s list to the rescue!

Fast forward to summer of last year, I decided to start studying for the OSCP certification again. However, I was still intent on not extending my lab time until I felt fully prepared. I did a lot of research on resources that have been helpful to previous students. The most useful resource that I came across was [TJ\_Null’s list of Hack The Box OSCP-like VMs](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#).

Close to that time as well, a friend of mine asked if I would be interested in leading a “[Pentesting Fundamentals](https://www.meetup.com/bdbskills/events/263121432/)” study group as part of an organization she founded formerly known as [Secure That Cert!](https://www.meetup.com/bdbskills/events/263121432/). I wouldn’t be teaching the material itself but instead I would design the syllabus and facilitate the discussions during the study sessions. So I figured what better way to force myself to follow a strict study schedule than the debilitating fear of not being prepared for a session that I’m in charge of facilitating! 

I designed the syllabus to cover a chapter of the CompTIA Pentest+ book and two boxes from TJ\_Null’s list of HTB boxes each week. The idea was that we read the assigned chapter and work on the boxes before the session and during the session we discuss what we learnt and watch [IppSec’s way](http://IppSec%27s%20videos%20of%20TJ_Null%27s%20list%20of%20Hack%20the%20Box%20OSCP-like%20VMs) of solving the HTB boxes. I think everyone that was part of the study group agreed on the fact that \(1\) the Pentest+ book was completely useless, and \(2\) the most useful resource was learning and adopting IppSec’s methodology of how to solve the HTB boxes.

As part of wanting to be prepared for the sessions, I made the decision to solve the assigned boxes for each week and publish writeups before we discuss them during the study session. This was a way to \(1\) ensure that I properly understand how to solve the box, and \(2\) anticipate any questions that might come up on the background knowledge needed to complete the box. 

{% embed url="https://twitter.com/rana\_\_khalil/status/1173737649074593792" %}

The writeups proved to be useful in so many ways! So even after the study group had ended I made the decision to finish all the boxes in TJ\_Null’s list, which at the time was 47 boxes.

{% embed url="https://twitter.com/rana\_\_khalil/status/1239389075087515649" %}

So here’s advice \#2.

> If you have the time to blog about how you solved a box, I would definitely recommend that. If not, make sure you take detailed notes \(for yourself\) of the methodology you used to solve the box and the list of commands you ran. Don’t be the kind of person that solves a box and moves on. You’ll come across many different concepts /commands/technologies and there’s really no easy way of remembering everything off the top of your head. Trust me, you’ll thank me later!

## OSCP Labs — Second time’s a charm

Having done all 47 boxes I finally felt ready to enrol back into the OSCP labs. At the time, Offensive Security had announced a major update to the course introducing PWK v2. I enrolled in the latest version and opted for a one month lab subscription. 

Having experienced both PWK v1 and PWK v2, I can safely say that the rolled out update was a HUGE improvement. The course material went more in depth on methodology and attack vectors. It also assumed less background knowledge from readers. The labs were updated and patched. Other than the lab itself and your own dedicated practice VMs, you also get access to a target network that demonstrates a full walkthrough of a penetration test.

This time around, I pretty much knew everything that was covered in the course material, except for the Active Directory and Pivoting chapters. I opted for submitting the lab report which took about two and a half weeks to complete and resulted in a 285 page document. This left me with only a week and a half left in the OSCP labs. During that time, I compromised about 25 boxes in the public network including the big four and unlocked the IT network.

This leads me to advice \#3.

> If you have the time, I would strongly recommend completing TJ\_Null’s list of Hack The Box OSCP-like VMs and watching IppSec’s videos of how to solve them. You won’t know how accurate that list is until you start working on the boxes in the OSCP lab. That’s all I’m going to say.

After my lab time was over, I made the decision not to extend because I had a pretty good idea \(based on reviews\) on what would be on the exam and I knew extending my lab time would not necessarily help me in passing the exam. Plus, I was already burnt out from the months of work I did beforehand working on TJ\_Null’s list. That being said, here’s advice \#4.

> If you have the time and resources, I would recommend enrolling in the 3-month lab option. Even if you already have enough knowledge to pass the OSCP exam, the lab offers a great opportunity to practice pivoting and active directory attacks. This is definitely something that will come in handy in future penetration testing engagements. Might as well learn it now in a practice environment.

## OSCP Exam — The dreaded 24 hour exam

Before registering into the exam, I wanted to do a practice dry run to get in the zone of doing a 24 hour exam. So I reached out to the community on twitter and as usual the community responded!

{% embed url="https://twitter.com/digitalohm/status/1253165122106736646" %}

{% embed url="https://twitter.com/TJ\_Null/status/1253153919561326592" %}

I did both of the above suggested practice exams — one of them completely destroyed my confidence while the other restored some faith into my skill set. I’ll leave it up to the reader to figure out which one was the easy one. This brings me to advice \#5.

> There’s a huge benefit from doing a dry run test before the official exam. It helps you come into terms with the fact that you will get stuck on the exam day. More importantly, it allows you to assess your methodology when it comes to tackling several machines in a limited period of time.

At the time, I still had not scheduled the exam. I woke up one day, sat on my laptop as usual and realized I didn’t have anything else I felt I needed to study for the certification. That’s when I decided to book the exam for the next day.

During the exam, I got the passing points within the first 9.5 hours, hit a road block and didn’t get any points after that. I did make sure to take several 10–15 minute breaks and slept 4 hours. I personally thought the exam was difficult when I was doing it. I even remember messaging a friend and saying that it was “brutal” and that I hope I would never have to go through it again!

However, in the 24 hours after the exam, I sat down to work on the report and came to the realization that the exam machines were actually very simple. If it wasn’t for the stress of the exam, I would have been able to solve the boxes that I did solve in a maximum number of 4 hours on a normal day. The boxes were nothing compared to some of the boxes I solved on Hack the Box. This leads me to advice \#6.

> This is easier said than done, but try to take it easy on the exam day. The exam is designed so that you’re able to finish it in the timeframe that you’re given. Also, don’t be afraid to use your Metasploit attempt, even if it is early on in the exam. It’ll give you the confidence boost that you need. However, first make sure that you’re \(1\) unable to solve the box w/o Metasploit, and \(2\) the Metasploit module is very likely to work \(you only get to run it on one box!\)

I won’t say anything other than that about the exam because Offensive Security has strict rules on that. However, within a week of submitting my report, I received the long awaited email telling me I passed the exam from the first attempt!

{% embed url="https://twitter.com/rana\_\_khalil/status/1259451923700371456" %}

## Parting Thoughts

If you’ve made it this far, thank you for reading the entire blog! I thought it was worth sharing my journey considering it was not your typical _“I enrolled in the OSCP labs and immediately did the exam and passed”_  type of blog. 

The note I’d like to end on is that this is a beginner certification that is achievable as long as you put the time and effort into studying for it. If you’re struggling, it’s completely okay! Many others have struggled before you including myself. Take a moment, evaluate what you need to improve on and try again. There’s tons of resources put forth by the community that will definitely help you succeed. 

## Commonly Asked Q&A

I’ve had many people ask me questions that I don’t have time to individually answer. Therefore, the following are my answers to the most asked questions. 

#### **1. I’m a beginner, how do I get started? What do you recommend before OSCP?**

There is no one textbook that will teach you the material that you will need to pass the OSCP exam. If you’ve gotten this far in reading my blog, you’ll know that the way I started learning is just by picking up a random HTB box from TJ\_Null’s list that was rated ‘Easy’, tried solving it, got stuck and watched IppSec’s video of how to solve it. I kept repeating that cycle until I became comfortable with solving boxes on my own. One thing that I did notice is that with every box that I encountered, I learnt something new and that’s why I did all 47 boxes before going into the OSCP labs.

If you’re following the same path that I did and you’re finding it very difficult to solve boxes on your own, that’s completely fine! You sometimes can’t do what you’ve never seen before. It’s okay to look at other writeups for hints without feeling disheartened every time you do. An example that I like to use is an HTB box that made use of port knocking. I could have spent a whole week bashing my head against the wall trying to solve it and get nowhere in the end. Or I could try for a couple of hours myself, know when to seek help and make sure to check for this vector in the next box I solve.

I whole heartedly disagree with the misconstrued “Try Harder” mentality that a large portion of the community has adopted. It’s okay to ask for help when you’ve given it all you can but still hit a brick wall. I can rant about this topic for another five paragraphs, but I think I got my point across.

#### **2. Which service do I start enumerating first?**

The first thing you need to do is scan all 65535 TCP ports and the top UDP ports. I use an amazing tool called [AutoRecon](https://github.com/Tib3rius/AutoRecon) which is allowed on the OSCP exam. The default port scan profile performs a full TCP port scan, a top 20 UDP port scan, and a top 1000 TCP port scan.

Once you’ve scanned all the ports, make a list of all the open ports. Start with weird services that you’ve never heard of before, identify the version of the installed software and then look for any associated critical CVEs such as remote code execution \(RCE\).

Once you’ve enumerated those services and crossed them off, move on to more common services such as SMB, FTP and HTTP. Keep in mind that sometimes you have to chain vulnerabilities from different services. HTTP has a very large attack vector, so it’s best to leave enumerating that service till the end.

#### **3. How do I avoid rabbit holes?** 

This is a tough question. I personally never had an issue with going down rabbit holes. I don’t know if it’s because I give up quickly on a service \(or functionality of a service\) when something doesn’t work or I have a finite amount of knowledge about each service and when I exhaust all the possibilities I just naturally move on to trying another vector. Take for example FTP. There’s really only four things you need to check for.

* Version number and associated CVEs
* Anonymous / authenticated login \(with discovered creds\)
* Sensitive files that you have read access to
* File upload

If you tried all the above items and none of them worked, you should cross off that service and never go back to it unless you discover something on another service that can give you further access \(that you didn’t originally have\) on this service. Developing this methodology comes with practice. I personally developed it by watching IppSec’s videos and working on TJ\_Null’s list of HTB OSCP-like VMs.

#### **4. I always get stuck on Windows boxes. Any general tips on how to improve that?**

Initial foothold is very similar whether you’re on a Windows or Linux box. The only major difference is the type of shell you use to gain an initial foothold on the box. It’s not as easy as using the [Reverse Shell Cheat Sheet from pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet). 

This [Windows PHP reverse shell](https://github.com/Dhayalanb/windows-php-reverse-shell) came in handy many times. Once you get a shell on the box, I always recommend converting it to a PowerShell shell if possible using the following command.

```text
powershell -exec bypass
```

An even better recommendation would be to get a PowerShell reverse shell from the get go using [Nishang scripts](https://github.com/samratashok/nishang) wherever possible. 

As for privilege escalation, I cover that in the next question. 

#### **5. I suck at privilege escalation. How do I get better?**

I personally took these two courses to improve my privesc knowledge.

* [Linux Privilege Escalation for OSCP & Beyond!](https://www.udemy.com/course/linux-privilege-escalation/)
* [Windows Privilege Escalation for OSCP & Beyond!](https://www.udemy.com/course/windows-privilege-escalation/)

I highly recommend them! I follow the author \([@TibSec](https://twitter.com/TibSec)\) on Twitter and he’s constantly updating the courses with any new & relevant privesc vectors. He’s also the author of AutoRecon tool which is pretty neat. One thing I would recommend is making a list of all the vectors outlined in the courses and testing them one-by-one when it comes to the OSCP exam. Sometimes the privesc vector is clear. However, when it’s not, start from the beginning and try each and every vector. 

Another privesc course that I heard really good things about, but haven’t taken myself is [Windows Privilege Escalation for Beginners](https://www.udemy.com/course/windows-privilege-escalation/) by The Cyber Mentor. These courses pretty much cost nothing but can go along way in improving your knowledge and saving you time on the OSCP labs and exam. 

#### **6. Would you recommend completing the lab report?**

Again, this is a tough question that I don’t have a solid answer to. I personally opted for doing the lab report and I believe it might have helped me pass the exam, so I’m happy that I made the decision to work on it and submit it. However, would I recommend that you take the same path? I don’t know. It would depend on your previous knowledge and the amount of lab time that you registered for amongst other factors.

#### **7. Which reporting tool did you use for notes and the exam?** 

I didn’t use any of the recommended tools such as CherryTree and Joplin. During the OSCP labs I documented everything in GitBook. The exam and lab reports were written in LaTeX. As for report format, I used the official [Offensive Security template](https://www.offensive-security.com/pwk-online/PWK-Example-Report-v1.pdf).

#### **8. Can you suggest new practice VMs from HTB or VulnHub that are inline with the PWK v2 update?**

No, [TJ\_Null](https://twitter.com/TJ_Null) has done a great job in maintaining and updating the list. Make sure to follow him on Twitter to receive any future updates. 

#### **9. Can you provide the list of resources that helped you pass the OSCP certification?**

Please refer to the _Resources_ section of this blog.

## Resources

This section is a compilation of all the resources that were mentioned in the blog.

* [TJ\_Null’s list of Hack the Box OSCP-like VMs](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#)
* [IppSec’s videos of TJ\_Null’s list of Hack the Box OSCP-like VMs](https://www.youtube.com/playlist?list=PLidcsTyj9JXK-fnabFLVEvHinQ14Jy5tf)
* [Hack the Box OSCP Preparation](https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/) 
* [Practical Ethical Hacking — The Complete Course](https://www.udemy.com/course/practical-ethical-hacking/)
* [Linux Privilege Escalation for OSCP & Beyond!](https://www.udemy.com/course/linux-privilege-escalation/)
* [Windows Privilege Escalation for OSCP & Beyond!](https://www.udemy.com/course/windows-privilege-escalation/)
* [Windows Privilege Escalation for Beginners](https://www.udemy.com/course/windows-privilege-escalation/)
* [AutoRecon](https://github.com/Tib3rius/AutoRecon)

