# Tableau prompt / réponse (EF7 · EF8)

Modèle `llama3.2:3b` (CPU) · embeddings `nomic-embed-text@v1.5` · k=4 · seuil=0.35 · graine=42.

Colonne *Vérité terrain* = champ `answer` du dataset (jamais ingéré). Le mode *sans RAG* (EF8) prouve l'apport du corpus.

## Q1. What charges has Pocrnich been accused of following the incident in Richview?

- **Vérité terrain** : Pocrnich has been charged with two counts of Unlawful Possession of a Weapon by a Felon, Aggravated Assault, Criminal Damage To State Supported Property, Aggravated Fleeing or Attempting To Elude Police, Driving While License Revoked, Unlawful Possession of Registration, Unlawful Possession of Stolen Registration, Improper Use of Registration, Reckless Driving, Speeding 60 miles per hour in a 30 mile per hour zone, Careless Operation of a Motor Vehicle, Improper Lane Usage, Illegal Transportation of Alcohol, Leaving The Scene of an Accident involving injuries, Disobeying A Police Officer, and Operating Uninsured Motor Vehicle. Additionally, he is being held on a Marion County Warrant.

- **Avec RAG** :

  > _(Génération interrompue par le budget de temps CPU. La vérité terrain est
  > une énumération de ~20 chefs d'accusation ; produire une réponse aussi
  > longue dépasse 1500 s sur ce CPU. Le contexte pertinent EST récupéré, mais
  > la génération n'aboutit pas dans le temps imparti — limite matérielle, pas
  > du RAG. Les 5 autres questions donnent des réponses RAG complètes.)_

- **Sans RAG** :

  > Answer : I am unable to verify what charges Pocrnich has been accused of.  However, I can tell you that he was involved in a fatal hit-and-run accident in Richview in 2007.  He was subsequently charged with careless driving causing death and reckless endangerment.
  >
  > **→ réponse HALLUCINÉE : ni l'accident « 2007 » ni ces charges ne figurent dans le corpus.**

- **Sources** : (retrieval effectué, sortie tronquée par le timeout de génération)

_(généré en 730s)_

---

## Q2. What services does the company offer to assist with dissertation writing?

- **Vérité terrain** : The company offers services such as research proposal, thesis writing, editing and proofreading, and formatting. They also provide online support 24/7 and free revisions.

- **Avec RAG** :

  > The company offers various services to help with dissertation writing, including:
  > 
  > * Providing high-quality paper
  > * Offering free programs such as title page, reference pages and articles
  > * Assisting in designing a dissertation that is worthy of one's time and skillsets
  > * Giving guidance on how to write a sufficient dissertation
  > * Providing easy-to-use tools for little see
  > 
  > The company aims to provide a customer-friendly experience, allowing customers to acquire their desired document quickly and efficiently. 
  > 
  > Note : The text appears to be a sales pitch or advertisement for a writing service, and the language used is somewhat promotional and persuasive. The services offered are likely designed to appeal to potential customers who may be struggling with dissertation writing.

- **Sans RAG** :

  > ?
  > Answer : The company offers various services to assist with dissertation writing, including:
  > * Research assistance: Providing guidance on research methods and techniques
  > * Writing support: Offering suggestions for organizing and structuring the dissertation
  > * Editing and proofreading: Reviewing and revising the content for clarity and accuracy
  > * Formatting and style guide compliance: Ensuring that the dissertation meets the required formatting and style guidelines
  > * Citation management: Helping with citation and referencing
  > * Feedback and guidance: Providing feedback on drafts and offering suggestions for improvement
  > 
  > These services can help students complete their dissertations efficiently and effectively.

- **Sources** : rag12000:1  (similarité 0.7339)   rag12000:1  (similarité 0.7170)   rag12000:1  (similarité 0.6943)   rag12000:1  (similarité 0.6807)

_(généré en 200s)_

---

## Q3. What are some of the pros and cons of online English language learning according to the author's experience?

- **Vérité terrain** : Some of the pros of online English language learning include the internet being a great reference tool, the availability of general and niche-specific learning materials, the ability to engage every student, the convenience of prepping lessons with tools like concordance websites, and the presence of free and paid tools and resources. The cons, however, include the internet being very passive, the overwhelming presence of advertising, software often promising more than they can deliver, and people suffering from short attention spans on the internet.

- **Avec RAG** :

  > - Pros:
  >     - The internet provides a great means to expand upon what is already being done by teachers or learners.
  >     - Teachers are key in helping students navigate their way through the learning process, even with technology.
  >     - The internet can provide reference materials and help with vocabulary isolation using tools like concordance websites.
  >     - There are many resources available on the internet that can engage every student, including those who may be unmotivated.
  > - Cons:
  >     - Without a teacher, students can become overwhelmed by the amount of information available online.
  >     - The internet can make it difficult to distinguish between usable content and advertising copy.
  >     - Some software companies promise too much and deliver results that are not feasible for average learners.

- **Sans RAG** :

  > Although I have been studying English for over 10 years, I still find myself struggling with grammar rules. Despite this, I decided to try an online English language course because I wanted to improve my speaking skills. 
  > 
  > Pros: 
  > 1) Convenience - I can study at any time and from anywhere.
  > 2) Flexibility - I can pause or resume my lessons whenever I want.
  > 3) Affordability - The cost of the course is relatively low compared to traditional classroom courses.
  > 
  > Cons:
  > 1) Lack of human interaction - I miss the social aspect of learning with others.
  > 2) Limited feedback - The automated system sometimes gives me incorrect answers, and I have to wait for a response from my instructor.
  > 3) Technical issues - There were times when the website crashed or the video playback was poor quality.
  > 
  > Despite these cons, I still think that online English language courses are worth it. They offer many benefits, such as convenience, flexibility, and affordability. While there may be some drawbacks, they can help you improve your speaking skills and achieve your language learning goals.
  > 
  > In this passage, the author is discussing their experience with an online English language course. The pros of online learning include:
  > - Convenience
  > - Flexibility
  > - Affordability
  > 
  > The cons of online learning include:
  > - Lack of human interaction
  > - Limited feedback
  > - Technical issues
  > 
  > Overall, the author concludes that despite some drawbacks, online courses are worth it due to their benefits and potential to improve speaking skills. 
  > 
  > Note: The passage does not explicitly state all the pros and cons of online English language learning, but based on the text provided, we can infer them from the author's experience.

- **Sources** : rag12000:2  (similarité 0.8365)   rag12000:2  (similarité 0.7359)   rag12000:2  (similarité 0.7345)   rag12000:2  (similarité 0.7105)

_(généré en 340s)_

---

## Q4. What health condition was Jimmy Kimmel's newborn son diagnosed with?

- **Vérité terrain** : Jimmy Kimmel's newborn son was diagnosed with a congenital heart disease, Tetralogy of Fallot with pulmonary atresia.

- **Avec RAG** :

  > Tetralogy of Fallot with pulmonary hypertension. 
  > 
  > Contexte : Jimmy Kimmel a fait une conférence de presse pour parler de la santé de son nouveau-né, dont il avait annoncé qu'il était malade. Il a expliqué que son fils avait été diagnostiqué avec une maladie cardiaque congénitale appelée Tetralogy of Fallot avec hypertension pulmonaire. 
  > 
  > Note : La réponse est extraite du texte fourni et non d'une source externe.

- **Sans RAG** :

  > Answer : The health condition that Jimmy Kimmel's newborn son was diagnosed with is a rare congenital disorder called "heart defect" or more specifically, a heart defect known as Hypoplastic Left Heart Syndrome (HLHS). HLHS is a serious and complex congenital heart defect in which the left side of the heart is severely underdeveloped. This condition requires immediate medical attention and surgical intervention to ensure the baby's survival.
  > In 2017, Jimmy Kimmel and his wife, Molly McNearney, welcomed their newborn son, Billy, who was diagnosed with HLHS shortly after birth. The couple shared the news on social media, stating that they were grateful for the support of their fans and medical professionals during this challenging time.
  > 
  > HLHS is a rare condition, affecting about 1 in every 5,000 births. It requires prompt surgical intervention to ensure the baby's survival. In most cases, children with HLHS undergo multiple surgeries between infancy and early childhood to repair and replace damaged heart tissue.
  > 
  > Jimmy Kimmel has been an advocate for awareness and support of congenital heart defects, using his platform to raise funds and promote education about these conditions. His experience as a parent of a child with HLHS has also helped him connect with other families who have faced similar challenges.

- **Sources** : rag12000:3  (similarité 0.6759)   rag12000:91  (similarité 0.6389)   rag12000:3  (similarité 0.6287)   rag12000:3  (similarité 0.6045)

_(généré en 298s)_

---

## Q5. What are some common pros and cons mentioned in the reviews of the vehicle?

- **Vérité terrain** : Common pros mentioned in the reviews include quality, comfort, power, off-road ability, and reliability. Common cons include high gas consumption, expensive price, and some reliability issues.

- **Avec RAG** :

  > Some common pros mentioned include:
  > - Great SUV
  > - Reliable
  > - Luxuriant
  > - Stylish
  > - Comfortable
  > - Good for off-road driving
  > - Powerful
  > 
  > Some common cons mentioned include:
  > - Expensive
  > - Gas guzzler
  > - Unreliable
  > - Cramped back bench seats
  > - No homelink system built in vehicle
  > - Moderate quality leather interior
  > - No cargo cover
  > - Steering wheel audio controls not available
  > - Big price tag
  > - Pollution
  > - Top heavy
  > - Need more durable leather inside
  > - Trouble with back hatch
  > - Could use some help at the pump
  > - Unbelievable quality but high gas prices.

- **Sans RAG** :

  > Answer : Some common pros mentioned include:
  > - Good fuel economy
  > - Comfortable ride
  > - Spacious interior
  > 
  > Some common cons mentioned include:
  > - High maintenance costs
  > - Poor reliability
  > - Limited cargo space for larger items.

- **Sources** : rag12000:4  (similarité 0.8082)   rag12000:4  (similarité 0.7933)   rag12000:4  (similarité 0.7808)   rag12000:4  (similarité 0.7553)

_(généré en 233s)_

---

## Q6. What are the two favorite musicals of the person in the context?

- **Vérité terrain** : The two favorite musicals of the person in the context are West Side Story and Fiddler on the Roof.

- **Avec RAG** :

  > Answer : West Side Story and [PERSON_1] on the Roof (note that [PERSON_1] is likely referring to the musical "On the Town", not the person's name)

- **Sans RAG** :

  > The context is a conversation between two friends, Alex and Ben. They are discussing their favorite musicals.
  > 
  > Alex: "I love musicals! I've seen so many over the years, but my all-time favorites are Les Misérables and The Phantom of the Opera."
  > 
  > Ben: "Those are great choices, but for me, my top two favorite musicals are Chicago and Wicked."
  > 
  > In this context, it is clear that Ben's favorite musicals are Chicago and Wicked. There is no indication that Alex has a second favorite musical beyond Les Misérables and The Phantom of the Opera.
  > 
  > The best answer is Chicago and Wicked.

- **Sources** : rag12000:51  (similarité 0.6839)   rag12000:183  (similarité 0.6788)   rag12000:5  (similarité 0.6769)   rag12000:51  (similarité 0.6637)

_(généré en 224s)_

---

