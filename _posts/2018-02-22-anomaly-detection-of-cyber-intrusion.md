---
layout: post
title: "Anomaly Detection of Cyber Intrusion"
date: 2018-02-22
excerpt: "My Capstone Project"
tags: [project]
feature: https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/cybersecurity-image.jpg
comments: true
---

# Anomaly Detection of Cyber Intrusion

## Introduction

With the ever improving networking technologies, our world is now more
connected than ever. The number of internet users has been growing
exponentially every year and is increasing at a high pace as you read.[^1]


This advancement leads to the greater possibilities in areas such as the
Internet of Things (IoT). IoT are any devices with the capability to be
connected to the internet. It can be your fitness tracker, the
self-driving car, a smart home appliance or even heart monitor implants.
It is predicted that by 2020, there will be 200 billion 'smart' devices
around.

IoT is becoming a commonplace in most parts of our life and as such our
reliance on them increases the value of hacking.

It is therefore of paramount importance that the cybersecurity field
grows along as well.

## Objective

As my capstone project for the Data Science Immersive Course I partake
under General Assembly, I will explore the effectiveness of machine
learning techniques on detecting cyber threats via networking traffic
flows data.

The main goal is to be able to detect most of the cyber threats (meaning
a high recall rate for the hostile traffic flows). The secondary goal is
then to make sure that there's as little false alarms as possible (high
precision rate).

## Dataset

The Intrusion Detection Evaluation Dataset (CICIDS2017) was obtained
from University of New Brunswick.

It contains **15 types of labelled flows** (Benign and up-to-date common
attacks) and approximately **2.8 mil rows** and **85 columns** consisting of
**forward flows** (Network flow from initiator to destination) and **backward flows**
(Network flow from destination back to initiator).

Most of the features can generally be grouped into the following:

1.  **IP Addresses --** Source\_IP, Destination\_IP

2.  **Ports --** Source\_Port, Destination\_Port

3.  **Transport Protocol (TCP:6, UDP:17) -** Protocol

4.  **Number of packets --** Total\_Fwd\_Packets, Total\_Backward\_Packets, Subflow\_Fwd\_Packets, Subflow\_Bwd\_Packets, Flow\_Packets\_persec, act\_data\_pkt\_fwd,

5.  **Packet Size --** Total\_Length\_of\_Fwd\_Packets,
    Total\_Length\_of\_Bwd\_Packets, Fwd\_Packet\_Length\_Max,
    Fwd\_Packet\_Length\_Min, Fwd\_Packet\_Length\_Mean,
    Fwd\_Packet\_Length\_Std, Bwd\_Packet\_Length\_Max,
    Bwd\_Packet\_Length\_Min, Bwd\_Packet\_Length\_Mean, Bwd\_Packet\_Length\_Std,
    Flow\_Bytes\_persec, Subflow\_Fwd\_Bytes, Subflow\_Bwd\_Bytes,
    Min\_Packet\_Length, Max\_Packet\_Length, Packet\_Length\_Mean,
    Packet\_Length\_Std, Packet\_Length\_Variance,
    Average\_Packet\_Size, min\_seg\_size\_forward,
    Init\_Win\_bytes\_forward, Init\_Win\_bytes\_backward

6.  **Packet Header Size --** Fwd\_Header\_Length, Bwd\_Header\_Length

7.  **Flow Duration --** Flow\_Duration

8.  **Amount of time a flow was active before going idle --**
    Active\_Mean, Active\_Std, Active\_Max, Active\_Min

9.  **Amount of time a flow was idle before becoming active --**
    Idle\_Mean, Idle\_Std, Idle\_Max, Idle\_Min

10. **Inter Arrival Time (time between 2 packets sent) --**
    Flow\_IAT\_Mean, Flow\_IAT\_Std, Flow\_IAT\_Max, Flow\_IAT\_Min,
    Fwd\_IAT\_Total, Fwd\_IAT\_Mean, Fwd\_IAT\_Std, Fwd\_IAT\_Max,
    Fwd\_IAT\_Min, Bwd\_IAT\_Total, Bwd\_IAT\_Mean, Bwd\_IAT\_Std,
    Bwd\_IAT\_Max, Bwd\_IAT\_Min

11. **TCP flags** **(TCP flags are used within TCP packet transfers to
    indicate a particular connection state or provide additional
    information) --** Fwd\_PSH\_Flags, Bwd\_PSH\_Flags, Fwd\_URG\_Flags,
    Bwd\_URG\_Flags, FIN\_Flag\_Count, SYN\_Flag\_Count,
    RST\_Flag\_Count, PSH\_Flag\_Count, ACK\_Flag\_Count,
    URG\_Flag\_Count, CWE\_Flag\_Count, ECE\_Flag\_Count

12. **Flow labels --** Label 
    (The 15 labels are: BENIGN, FTP-Patator, SSH-Patator, DoS slowloris, DoS Slowhttptest, DoS Hulk, DoS GoldenEye, Heartbleed, Web Attack -- Brute Force, Web Attack -- XSS, Web Attack -- Sql Injection, Infiltration, Bot, DDoS , PortScan)

**Citation:** *Iman Sharafaldin, Arash Habibi Lashkari, and Ali A.
Ghorbani, "Toward Generating a New Intrusion Detection Dataset and
Intrusion Traffic Characterization", 4th International Conference on
Information Systems Security and Privacy (ICISSP), Purtogal, January
2018*

## Data Wrangling

**Handling of null values:**

There were *1358* observations with null values found in the feature
*'Flow\_Bytes\_persec'*. Looking into the feature, I discovered that
there were *1509* entries label as 'Infinity'.

A cross check with the other time-based feature,
*'Flow\_Packets\_persec'*, I found *2867* 'Infinity' entries, which
is the same amount for *'Flow\_Bytes\_persec'* if you sum up the
count of null values and 'Infinity' entries. This more of less
confirm that the null values were supposed to be marked as
'Infinity'.

Now, both the features are supposed to be float values, why was it
marked as 'Infinity' then? Checking up some rows with
*\'Flow\_Packets\_persec\'* and *\'Flow\_Bytes\_persec\'* not being
'Infinity', it seems that they were derived from taking either
*\'Total\_Fwd\_Packets\'* + *\'Total\_Backward\_Packets\'* or
*\'Total\_Length\_of\_Fwd\_Packets\'* +
*\'Total\_Length\_of\_Bwd\_Packets\'* and divided by
*\'Flow\_Duration\'. *

Looking into the *'Flow\_Duration'* column and found that those
\'Infinity\' values were derived due to *\'Flow\_Duration\'*(the
denominator) being 0.

Therefore, I replaced these missing and \'Infinity\' values with
either *its \'Total\_Fwd\_Packets\'* + *\'Total\_Backward\_Packets*
or *\'Total\_Length\_of\_Fwd\_Packets\'* +
*\'Total\_Length\_of\_Bwd\_Packets\'.*

**Negative values:**

I also found some negative values that did not make sense in 'Flow
Duration', \'Fwd\_Header\_Length\', \'Init\_Win\_bytes\_forward\',
\'Init\_Win\_bytes\_backward\'.

Upon checking that these observations belong to the majority class
'BENIGN', which we have no shortage of, I decided to drop these
entries.

**Categorical Features:**

There are some categorical features that I found can be quite
useful.

The type of transfer protocol used. This feature was converted into
dummy variables, 'Protocol\_0', 'Protocol\_6', and 'Protocol\_17'.

The Source and Destination Port could potentially identify some of
the attacks that uses certain port numbers. However, after looking
up on the number of unique port numbers, there were too many (64k
for Source\_Port' and 53k for 'Destination\_Port') of them to create
dummy variables out of.

The port numbers in the range 0 to 1023 are the well-known ports or
system ports. They are used by system processes that provide widely
used types of network services. Therefore I labelled the ports as 1
if they are within the well-known ports, else 0.

**Changing of data type:**

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/change_type.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/change_type.PNG"></a>
</figure>

The data types of the features were changed in order to reduce
computational time for subsequent codes. Categorical features were
changed from string objects type to category type. The int64 and
float64 features were reduced to their respective datatype that can
handle their range of values.

After changing the types, the data size reduced from approx. 1.6GB
to approx. 750MB. (More than halved the size, Perfect!)

## Exploratory Data Analysis (EDA)

First, let's look into the distribution of class labels,

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/label.png"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/label.png"></a>
</figure>

You can see that the imbalances between the classes are huge, some of
the hostile classes are so scarce that they cannot be seen when plotted
together with the 'BENIGN' class.

The following is the proportion of the classes in numerical
representation:

  **Label**                    | **Count**|  **Proportion**
  -----------------------------| ---------|----------------
  BENIGN                       | 2359289  |   0.8334521
  Bot                          | 1966     |   0.00069513
  DDoS                         | 41835    |   0.01477914
  DoS GoldenEye                | 10293    |   0.0036367
  DoS Hulk                     | 231073   |   0.0816306
  DoS Slowhttptest             | 5499     |   0.0019435
  DoS slowloris                | 5796     |   0.0020484
  FTP-Patator                  | 7938     |   0.0028042
  Heartbleed                   | 11       |   0.0000048
  Infiltration                 | 36       |   0.00001312
  PortScan                     | 158930   |   0.056144
  SSH-Patator                  | 5897     |   0.0020833
  Web Attack -- Brute Force    | 1507     |   0.0005329
  Web Attack -- Sql Injection  | 21       |   0.00000711
  Web Attack -- XSS            | 652      |   0.0002301

Hostile classes such as *'Heartbleed', 'Infiltration', 'Web Attack --
Sql Injection', 'Bot', 'Web Attack -- Brute Force'* and *'Web Attack --
XSS'* are indeed very scarce (not even 0.01% of whole dataset!), it will
likely be very difficult to class these accurately but let's see what I
can do.

Next, I plotted the distribution plots of all 72 of the numerical
features, each feature comparing the distribution between the benign
class and hostile classes. Because of the large amount of benign class,
the hostile classes' distribution were not very visible in the each feature's
plot. (please click <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/features_dist.png">**here**</a> to view the plots)

## Features Selection

There are various methods available to select features.

I first attempted to eliminate features by applying LASSO penalty with a
cross validated logistic regression on the dataset. By doing that the
LASSO penalty will shrink coefficients of weaker features to zero.
However, it seems like due to the size of the data, the code did not
manage to complete even after a day (24hrs).

To move on due to the limited time frame I have, I tried Recursive
feature elimination (RFE) next. RFE repeatedly constructs a model (in my
case logistic regression), sets aside either the best or worst
performing feature in predicting the target variable and then repeating
the process with the rest of the features. Features are then ranked
according to when they were eliminated. Similarly, this method was too
time consuming for the dataset.

Finally, I opted to select the features with highest pearson correlation
with the target variable. The highest correlation were 0.287476 and
-0.287116. I decided to filter out features with less than 0.05
correlation and with the remaining features, I plotted a heatmap:

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/heatmap.png"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/heatmap.png"></a>
</figure>

With the heatmap, I was able to remove the independent features which
have high correlation with other independent features, in order to
prevent multicollinearity.

Multicollinearity increases the variance of the coefficient estimates
and make the estimates very sensitive to minor changes in the model.
This will result in the coefficient estimates being unstable and
difficult to interpret.

After eliminating the highly correlated features, the following 17
features were chosen:

\'Protocol\_6\', \'PSH\_Flag\_Count\', \'Bwd\_Packet\_Length\_Std\',
\'Fwd\_IAT\_Std\', \'min\_seg\_size\_forward\',
\'Bwd\_Packets\_persec\', FIN\_Flag\_Count\', \'Idle\_Std\',
\'Flow\_IAT\_Mean\', \'Bwd\_IAT\_Std\', \'Bwd\_IAT\_Total\',
\'Init\_Win\_bytes\_backward\', \'SYN\_Flag\_Count\',
\'Avg\_Fwd\_Segment\_Size\', \'Fwd\_Packet\_Length\_Min\',
\'URG\_Flag\_Count\', \'Destination\_Port\'

**RadViz Plot**

RadViz is a multivariate data visualization algorithm that 
plots each axis uniformly around the circumference of a circle 
then plots points on the interior of the circle such that the 
point normalizes its values on the axes from the center to 
each arc

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/radviz.png"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/radviz.png"></a>
</figure>

As seen from the RadViz plot, there are no clear distinction between the
classes. They seem to overlap each other quite badly.

## Modeling

**Approach:**

-   Logistic Regression without balancing the dataset

-   Logistic Regression with balanced class weights

-   Resampling methods from Imblearn Package (Logistic regression was
    ran to find out the most effective resampling method) :

    -   Undersampling: Random Undersampling

    -   Undersampling: Tomek's Link

    -   Oversampling: Random Oversampling

    -   Oversampling: Synthetic Minority Oversampling Technique (SMOTE)

    -   Customised Over and Under sampling: Multi-resampler

-   With the most effective sampling method, further classification
    models were ran

    -   K-Nearest Neighbors (KNN)

    -   Support Vector Machine (SVC)

    -   Ensemble Support Vector Machine (SVC)

    -   Random Forest Classifier

-   Unsupervised learning: Isolation Forest

### Logistic Regression without balancing the dataset

Here we will begin with running Logistic Regression without handling the
imbalance in data, this will be the benchmark result that we will aim to
better. Without handling the heavily imbalanced data the trained model
will likely have difficulties predicting the minority classes on the
test set.

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/1a_logregnobal.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/1a_logregnobal.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/1b_logregnobal_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/1b_logregnobal_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/1c_logregnobal_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/1c_logregnobal_cm.PNG"></a>
</figure>

As expected, the model has difficulty predicting the minority classes,
with most of them having 0 recall and precision. The number of hostile
traffics that were misclassified as benign traffic seems large. We will
now proceed with a simple balancing of data by choosing balanced for the
logistic regression\'s class weights and see how much the result
improve.

### Logistic Regression with balanced class weights

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/2a_logregbal.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/2a_logregbal.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/2b_logregbal_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/2b_logregbal_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/2c_logregbal_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/2c_logregbal_cm.PNG"></a>
</figure>

This is quite surprising, by just assigning more weights to the minority
classes when performing logistic regression actually improves the result
quite significantly, with 412 attacks classified as benign traffic.
However, there still seem to be quite a number of misclassification. We
will now proceed to try out some resampling methods using the
imbalanced-learn package.

### Undersampling: Random Undersampling

For RandomUnderSampler, by default the ratio to be resampled is set as
\'auto\' where the all classes are shrunk to the count of the smallest
minority class.

In this case the other classes were shrunk to 8 counts. The logistic
regression results was much worse than the benchmark result.

Therefore, an ideal resampled ratio has to be entered to prevent that.
Here, the classes with counts \> 4000 were shrunk to 4000 and those with
\< 4000 will remain as they are.

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/3a_rus.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/3a_rus.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/3b_ruslogreg.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/3b_ruslogreg.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/3c_ruslogreg_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/3c_ruslogreg_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/3d_ruslogreg_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/3d_ruslogreg_cm.PNG"></a>
</figure>

A balanced class weight was applied to give more weightage to the
smaller classes. The results seem better, with 152 attacks classified as
benign traffic.

### Undersampling: Tomek's Link

Same ratio as random under sampling was applied. However, it seems that
Tomek was unable to downsample to that ideal ratio.

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/4a_tomek.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/4a_tomek.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/4b_tllogreg.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/4b_tllogreg.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/4c_tllogreg_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/4c_tllogreg_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/4d_tllogreg_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/4d_tllogreg_cm.PNG"></a>
</figure>

The results were worse than that of random
undersampling and just using balanced class weights without resampling.
2103 attacks classed as benign.

### Oversampling: Random Oversampling

For RandomOverSampler, the ratio was enter for the minority classes
instead. This is to prevent all minority classes being up sampled to the
size of the benign class (1769353 counts). The classes with counts less
than 4000 were up sampled to 4000 and those with more than 4000 will
remain as they are.

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/5a_ros.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/5a_ros.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/5b_roslogreg.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/5b_roslogreg.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/5c_roslogreg_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/5c_roslogreg_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/5d_roslogreg_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/5d_roslogreg_cm.PNG"></a>
</figure>

The results is relatively good but the
RandomUnderSampler still had better results. 207 attacks classed as
benign.

### Oversampling: Synthetic Minority Oversampling Technique (SMOTE)

Same ratio used as the RandomOverSampler.

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/6a_smote.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/6a_smote.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/6b_smotelogreg.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/6b_smotelogreg.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/6c_smotelogreg_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/6c_smotelogreg_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/6d_smotelogreg_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/6d_smotelogreg_cm.PNG"></a>
</figure>

SMOTE seems to have performed quite well for us here, it is the better
oversampler compared to RandomOverSampler. The number of attacks wrongly
classed as benign is only 103.

### Customised Under and Over sampling: Multi-resampler

As the previous sampling methods only managed to either down sample or
up sample, I thought it might be a good idea to combine both methods.

The following function first finds the mean or median count of all
classes. Next, it under sample the classes with counts higher than
mean/median to that mean/median count. Lastly, it over sample the
classes with counts lower than mean/median to that mean/median count.

With this method the class count will balance up nicely.

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/7_ms function.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/7_ms function.PNG"></a>
</figure>
I first tried using the mean count as the ratio to balance the data up.
The under sampler and over sampler used were set as default
(RandomUnderSampler and RandomOverSampler).

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/7a_msmean.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/7a_msmean.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/7b_msmeanlogreg.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/7b_msmeanlogreg.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/7c_msmeanlogreg_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/7c_msmeanlogreg_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/7d_msmeanlogreg_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/7d_msmeanlogreg_cm.PNG"></a>
</figure>

Pretty decent results. 106 attacks wrongly classed as benign.

Next, I proceeded with using the median as ratio.

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/8a_msmed.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/8a_msmed.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/8b_msmedlogreg.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/8b_msmedlogreg.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/8c_msmedlogreg_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/8c_msmedlogreg_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/8d_msmedlogreg_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/8d_msmedlogreg_cm.PNG"></a>
</figure>

Even better results using the median
value. Only 95 attacks were wrongly classed as benign.

Lastly, I will try changing the oversampler to SMOTE, since it produced
better results than RandomOverSampler previously.

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/9a_smotems.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/9a_smotems.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/9b_smotemslogreg.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/9b_smotemslogreg.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/9c_smotemslogreg_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/9c_smotemslogreg_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/9d_smotemslogreg_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/9d_smotemslogreg_cm.PNG"></a>
</figure>

Best results we have gotten so far using just logistic regression! There are only 71 attacks wrongly classed as benign.

### Result Summary: 
| **Model** | **Attacks  Undetected** | **Weighted Average  Precision** | **Weighted Average  Recall** | **Weighted Average  f1-score** |
|:---------:|:-----------------------:|:-------------------------------:|:----------------------------:|:------------------------------:|
| Logistic Regression without balancing | 22,081 | Unreliable as many classes were not predicted | Unreliable as many classes were not predicted | Unreliable as many classes were not predicted |
| Logistic Regression with balanced class weights | 412 | 0.94 | 0.70 | 0.79 |
| **RandomUnderSampler:** Logistic Regression with balanced class weights | 152 | 0.94 | 0.71 | 0.79 |
| **TomekLink:** Logistic Regression with balanced class weights | 2103 | 0.94 | 0.69 | 0.78 |
| **RandomOverSampler:** Logistic Regression with balanced class weights | 207 | 0.94 | 0.75 | 0.82 |
| **SMOTE:** Logistic Regression with balanced class weights | 103 | 0.95 | 0.75 | 0.82 |
| **Multi-resampler (Mean):** Logistic Regression with balanced class weights | 106 | 0.95 | 0.74 | 0.81 |
| **Multi-resampler (Median):** Logistic Regression with balanced class weights | 95 | 0.94 | 0.72 | 0.80 |
| **Multi-resampler (Median and SMOTE):** Logistic Regression with balanced class weights | 71 | 0.94 | 0.72 | 0.79 |

Multi-resampler (Median and SMOTE) is the best resampling technique for our objective.

We will now explore a few other classification models to see if we can further decrease the attacks misclassed as benign.

Starting off with k-Nearest Neighbors,
<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/10a_smsknn_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/10a_smsknn_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/10b_smsknn_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/10b_smsknn_cm.PNG"></a>
</figure>

The number of attacks wrongly classed as benign is at 16433, that is quite far away from the results we got from logistic regression.

Next, we will use Support Vector Machine for classification.

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/11a_smssvc.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/11a_smssvc.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/11b_smssvc_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/11b_smssvc_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/11c_smssvc_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/11c_smssvc_cm.PNG"></a>
</figure>

128 attacks went undetected. Seems quite decent but logistic Regression still performed best.

Next we will try an ensemble method, Random Forest Classifier.

<figure>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/12a_smsrf.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/12a_smsrf.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/12b_smsrf_classrpt.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/12b_smsrf_classrpt.PNG"></a>
    <a href="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/12c_smsrf_cm.PNG"><img src="https://raw.githubusercontent.com/raydenchua/raydenchua.github.io/master/assets/img/anomaly/12c_smsrf_cm.PNG"></a>
</figure>

2024 attacks went undetected, not the best model for our objective.

### Result Summary: 
| **Model** | **Attacks  Undetected** | **Weighted Average  Precision** | **Weighted Average  Recall** | **Weighted Average  f1-score** |
|:---------:|:-----------------------:|:-------------------------------:|:----------------------------:|:------------------------------:|
| **Multi-resampler (Median and SMOTE):** <br/>Logistic Regression with balanced class weights | 71 | 0.94 | 0.72 | 0.79 |
| **Multi-resampler (Median and SMOTE):** <br/>k-Nearest Neighbors | 16,433 | 0.94 | 0.88 | 0.90 |
| **Multi-resampler (Median and SMOTE):** <br/>Support Vector Machine (SVC) | 128 | 0.95 | 0.83 | 0.87 |
| **Multi-resampler (Median and SMOTE):** <br/>Random Forest Classifier | 2024 | 0.97 | 0.80 | 0.87 |

## Conclusion
To conclude, the customised resampler seems to work best. By finding a mid point (the median), it balances the data without losing too much information from each class.
With regards to the modelling, Logistic Regression is still the most effective, only 71 which is only 0.06% hostile traffic flows went undetected.
However, there is a tradeoff in the amount of false alarms there are (in this case 193,204 around 33% of all benign flows in the test set). 
If the model is deployed and solely relied on, the cost of looking into these false alarms could be high. 
That, historically, has been the issue of anomaly-based intrusion detection systems.

[^1]: <a href="http://www.internetlivestats.com/internet-users">Internet Users</a>