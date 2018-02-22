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
exponentially every year and is increasing at a high pace as you read.
http://www.internetlivestats.com/internet-users/

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

It contains 15 types of labelled flows (Benign and up-to-date common
attacks) and approximately 2.7 mil rows and 85 columns consisting of
forward flows (Flow initiator to Destination) and backward flows
(Destination back to Flow initiator).

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

For a more detailed description of each feature, please refer to the
excel file on **my github**.

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

![](media/image3.png){width="6.268055555555556in"
height="4.511805555555555in"}

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
the hostile classes' distribution were not visible in the each feature's
plot. (Due to the large number of plots, please refer to my **Jupyter
Notebook** to view the plots)

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

![](media/image4.png){width="6.268055555555556in"
height="4.309027777777778in"}

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

![](media/image5.png){width="6.2827066929133855in"
height="4.364583333333333in"}

As seen from the RadViz plot, there are no clear distinction between the
classes. They seem to overlap each other quite badly.

## Model

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

![](media/image6.PNG){width="6.268055555555556in"
height="1.163888888888889in"}![](media/image7.PNG){width="5.46951334208224in"
height="3.698432852143482in"}![](media/image8.PNG){width="6.268055555555556in"
height="3.675in"}

As expected, the model has difficulty predicting the minority classes,
with most of them having 0 recall and precision. The number of hostile
traffics that were misclassified as benign traffic seems large. We will
now proceed with a simple balancing of data by choosing balanced for the
logistic regression\'s class weights and see how much the result
improve.

### Logistic Regression with balanced class weights

![](media/image9.PNG){width="6.268055555555556in"
height="1.301388888888889in"}![](media/image10.PNG){width="5.490349956255468in"
height="3.604669728783902in"}![](media/image11.PNG){width="6.268055555555556in"
height="3.973611111111111in"}

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

![](media/image12.PNG){width="6.268055555555556in"
height="1.7805555555555554in"}![](media/image13.PNG){width="6.268055555555556in"
height="1.7180555555555554in"}![](media/image14.PNG){width="5.448676727909011in"
height="3.5629975940507435in"}![](media/image15.PNG){width="6.268055555555556in"
height="3.9743055555555555in"}

A balanced class weight was applied to give more weightage to the
smaller classes. The results seem better, with 152 attacks classified as
benign traffic.

### Undersampling: Tomek's Link

Same ratio as random under sampling was applied. However, it seems that
Tomek was unable to downsample to that ideal ratio.

![](media/image16.PNG){width="6.268055555555556in"
height="1.8694444444444445in"}![](media/image17.PNG){width="6.268055555555556in"
height="1.7326388888888888in"}![](media/image18.PNG){width="5.479931102362205in"
height="3.594251968503937in"}![](media/image19.PNG){width="6.268055555555556in"
height="3.928472222222222in"}The results were worse than that of random
undersampling and just using balanced class weights without resampling.
2103 attacks classed as benign.

### Oversampling: Random Oversampling

For RandomOverSampler, the ratio was enter for the minority classes
instead. This is to prevent all minority classes being up sampled to the
size of the benign class (1769353 counts). The classes with counts less
than 4000 were up sampled to 4000 and those with more than 4000 will
remain as they are.

![](media/image20.PNG){width="6.268055555555556in"
height="1.8881944444444445in"}![](media/image21.PNG){width="6.268055555555556in"
height="1.70625in"}![](media/image22.PNG){width="5.448676727909011in"
height="3.594251968503937in"}![](media/image23.PNG){width="6.268055555555556in"
height="3.879861111111111in"}The results is relatively good but the
RandomUnderSampler still had better results. 207 attacks classed as
benign.

### Oversampling: Synthetic Minority Oversampling Technique (SMOTE)

Same ratio used as the RandomOverSampler.

![](media/image24.PNG){width="6.268055555555556in"
height="1.8736111111111111in"}![](media/image25.PNG){width="6.268055555555556in"
height="1.2395833333333333in"}![](media/image26.PNG){width="5.459095581802274in"
height="3.5838331146106737in"}

![](media/image27.PNG){width="6.268055555555556in"
height="3.9069444444444446in"}

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

![](media/image28.PNG){width="6.268055555555556in"
height="4.013888888888889in"}

I first tried using the mean count as the ratio to balance the data up.
The under sampler and over sampler used were set as default
(RandomUnderSampler and RandomOverSampler).

![](media/image29.PNG){width="6.268055555555556in"
height="1.1104166666666666in"}![](media/image30.PNG){width="6.268055555555556in"
height="1.5923611111111111in"}![](media/image31.PNG){width="5.459095581802274in"
height="3.656760717410324in"}![](media/image32.PNG){width="6.268055555555556in"
height="3.8944444444444444in"}

Pretty decent results. 106 attacks wrongly classed as benign.

Next, I proceeded with using the median as ratio.

![](media/image33.PNG){width="6.268055555555556in"
height="1.1076388888888888in"}![](media/image34.PNG){width="6.268055555555556in"
height="1.4854166666666666in"}![](media/image35.PNG){width="5.479931102362205in"
height="3.6255063429571304in"}![](media/image36.PNG){width="6.268055555555556in"
height="3.8854166666666665in"}Even better results using the median
value. Only 95 attacks were wrongly classed as benign.

Lastly, I will try changing the oversampler to SMOTE, since it produced
better results than RandomOverSampler previously.

![](media/image37.PNG){width="6.268055555555556in"
height="1.1020833333333333in"}![](media/image38.PNG){width="6.268055555555556in"
height="1.16875in"}![](media/image39.PNG){width="5.46951334208224in"
height="3.656760717410324in"}![](media/image40.PNG){width="6.268055555555556in"
height="4.045138888888889in"}

Best results we have gotten so far using just logistic regression! There
are only 71 attacks wrongly classed as benign.

### Isolation Forest

Choose a random field. Look at the minimum value and max value in that
field and make some random split in between that space. Grow the tree
repeat until every point is isolated into a leaf node. The main
intuition is a point in low density space will tend to get isolated with
fewer random splits than points in higher density spaces. The depth of
high density spaces likely have deeper depth.
