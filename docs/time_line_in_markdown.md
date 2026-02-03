# Project Management

The project is divided into 4 Phases.
Each Phase is divided into 4 Tasksets. Additionally, each taskset will include a minimum of two hours of thesis work.

## Phase I: Research, design and setup
**~80 Hours**
*Focus: Infrastructure setup, risk analysis, architectural design, and selecting analysis tools.*

### Taskset Ia: Project Organization, Proposal and Orientation
**~25 Hours**

1. January 12, 2026 - January 18, 2026
    * [cite_start]**Setup:** Provision Virtual Machine on Frostbyte infrastructure[cite: 314, 323].
    * **Tools:** Initialize Git repository and set up Overleaf for the thesis.
    * [cite_start]**Planning:** Create the "Product Backlog" and define sprints/tasksets[cite: 76, 150].
    * **Thesis:** Outline the skeleton (Introduction, Background, Methodology).

2. January 19, 2026 - January 25, 2026
    * [cite_start]**Research:** Deep dive into the 4 specific attack vectors: SilentSync, Colorama/Colorizr, Credential Takeover, and Torchtriton[cite: 291, 292, 293, 294].
    * [cite_start]**Selection:** Finalize selection of specific AI APIs (Gemini/GPT-5/Anthropic) and SAST tools (Bandit/Semgrep)[cite: 277, 313].
    * **Thesis:** Write the "Project Description" and "Objectives" chapters.

### Taskset Ib
**~20 Hours**

3. January 26, 2026 - February 1, 2026
    * **Design:** Architect the system design (Simulator <-> Diffing Engine <-> Analysis Pipeline).
    * [cite_start]**Risk Analysis:** Create the formal Risk Analysis (Áhættugreining) document required for Sitrep 1. Define risks, impact, and mitigation strategies[cite: 124, 130].
    * **Thesis:** Draft the "State of the Art" / Background section regarding Supply Chain Attacks.

### Taskset Ic
**~20 Hours**

4. February 2, 2026 - February 8, 2026
    * **Prototyping:** Create a "Hello World" proof-of-concept connecting Python to the chosen LLM API.
    * [cite_start]**Environment:** Configure the Python 3.9+ development environment and install dependencies[cite: 311].
    * [cite_start]**Presentation:** Prepare slides for Sitrep 1 (Team, Project, Process, Risks)[cite: 204].
    * **Thesis:** Refine the Risk Analysis section for the report.

### Taskset Id
**~15 Hours**

5. February 9, 2026 - February 15, 2026: **1st Sitrep Meeting**
    * [cite_start]**Meeting:** Attend **Sitrep 1** (Week of Feb 9-13)[cite: 217]. Present status, time tracking, and risk analysis.
    * **Feedback:** Incorporate feedback from the supervisor/examiner into the project plan.
    * **Thesis:** Complete the first draft of the "Introduction" chapter.


## Phase II: Development of PyPI simulator and diffing engine.
**~100 Hours**
*Focus: Building the core engine that fetches packages, diffs them, and orchestrates the analysis.*

### Taskset IIa
**~25 Hours**

6. February 16, 2026 - February 22, 2026
    * **Dev (Simulator):** Implement the PyPI Simulator core. [cite_start]Create logic to fetch/ingest package versions[cite: 273].
    * **Dev (Storage):** Implement local storage/database for package metadata and archives.
    * **Thesis:** Document the "Simulator Architecture" in the Design chapter.

### Taskset IIb
**~25 Hours**

7. February 23, 2026 - March 1, 2026
    * **Dev (Diffing):** Implement the Diffing Engine. [cite_start]Logic to compare Version A vs. Version B and extract added/modified code[cite: 274].
    * **Testing:** Unit test the diffing logic to ensure it captures changes accurately.
    * **Thesis:** Write the "Diffing Methodology" subsection.

### Taskset IIc
**~25 Hours**

8. March 2, 2026 - March 8, 2026
    * **Dev (Orchestration):** Build the pipeline controller that passes the *Diff* to a "stub" analysis function (preparation for Phase III).
    * [cite_start]**Dev (Logging):** Implement the logging system to record detection results and false positives[cite: 278].
    * [cite_start]**Presentation:** Prepare slides for Sitrep 2 (Technical deep dive, Prototype demo)[cite: 207].
    * [cite_start]**Thesis:** Create system diagrams (Flowcharts/Sequence diagrams) for the report[cite: 159].

### Taskset IId
**~25 Hours**

9. March 9, 2026 - March 15, 2026: **2nd Sitrep Meeting**
    * [cite_start]**Meeting:** Attend **Sitrep 2** (Week of Mar 9-13)[cite: 218]. Show the Prototype/Diffing engine.
    * **Dev:** Refine the simulator based on testing results.
    * **Thesis:** Update the "Implementation" chapter with code snippets and architectural decisions.


## Phase III: Benchmarking Integration of industry standard SAST and experimental AI analysis tools
**~100 Hours**
*Focus: Integrating the detection tools and generating the dataset of malicious/benign packages.*

### Taskset IIIa
**~25 Hours**

10. March 16, 2026 - March 22, 2026
    * [cite_start]**Dev (SAST):** Integrate **Bandit** and **Semgrep** into the pipeline[cite: 312].
    * **Config:** Configure rulesets for SAST tools to target supply chain patterns.
    * **Thesis:** Document the SAST tools configuration and selection rationale.

### Taskset IIIb
**~25 Hours**

11. March 23, 2026 - March 29, 2026
    * [cite_start]**Dev (AI):** Integrate LLM APIs (Gemini/GPT) into the pipeline[cite: 277].
    * [cite_start]**Prompt Engineering:** Develop and test system prompts specifically for detecting the 4 attack vectors[cite: 269].
    * **Thesis:** Document the prompt engineering strategy and AI parameters.

### Taskset IIIc
**~25 Hours**

12. March 30, 2026 - April 5, 2026
    * **Dataset:** Create/Synthesize the "Malicious" dataset. [cite_start]Generate samples for: SilentSync, Colorama (typosquat), Credential Takeover, and Torchtriton (dependency confusion) [cite: 291-294].
    * [cite_start]**Control Group:** Select "Benign" control versions for each package to measure false positives[cite: 297].
    * **Thesis:** Write the "Experimental Setup" and "Dataset" sections.

### Taskset IIId
**~25 Hours**

13. April 6, 2026 - April 12, 2026
    * **Integration:** Connect all components: Simulator -> Diff -> SAST/AI -> Results DB.
    * **Dry Run:** Perform a full system test with a small subset of data.
    * **Thesis:** Finalize the "Methodology" chapter.

14. April 13, 2026 - April 19, 2026:  **TEST PERIOD (Exams)**
    * *Note: RU Exam Period starts.*
    * **Execution:** Run the automated benchmarking suite (long-running process). Let the system process the dataset.
    * **Thesis:** Low-intensity work: Review literature and citations.

15. April 20, 2026 - April 26, 2026: **TEST PERIOD (Exams)**
    * *Note: RU Exam Period continues.*
    * **Data Collection:** Monitor the benchmarking results. Ensure no crashes.
    * **Presentation:** Start drafting the final presentation slides and the "Generalprufa" (Sitrep 3) deck.


## Phase IV: Testing, data collection, and final thesis writing
**~100 Hours**
*Focus: Analyzing results, writing the conclusion, and preparing for the final defense.*

### Taskset IVa
**~25 Hours**

16. April 27, 2026 - May 3, 2026: **3rd Sitrep Meeting**, **Three Week Starts**
    * **Analysis:** Compile the results. [cite_start]Compare Detection Rates vs. False Positives for AI vs. SAST[cite: 285].
    * **Meeting:** Attend **Sitrep 3** (Week of Apr 27-30). [cite_start]This is the "Generalprufa" (Dress Rehearsal)[cite: 209, 219].
    * **Thesis:** Write the "Results" and "Evaluation" chapters.

### Taskset IVb
**~35 Hours**

17. May 4, 2026 - May 10, 2026
    * **Thesis:** Write "Discussion" and "Conclusion". Complete the Abstract.
    * [cite_start]**Documentation:** Write the `README.md` and user manuals for the GitHub repository[cite: 99].
    * [cite_start]**Review:** Full read-through of the thesis for spelling, grammar, and flow[cite: 227].

### Taskset IVc
**~30 Hours**

18. May 11, 2026 - May 17, 2026
    * [cite_start]**Final Code:** Polish code, remove debug statements, ensure repository is clean for submission[cite: 229].
    * **Submission:** Final formatting of the PDF. [cite_start]Submit Thesis to Skemman and code to Supervisors[cite: 226].
    * **Presentation:** Finalize the slide deck for the public defense.

### Taskset IVd
**~10 Hours**

19. May 18, 2026 - May 24, 2026: **Presentation of Final Project**
    * **Rehearsal:** Practice the presentation.
    * [cite_start]**Defense:** **Final Public Presentation** (Week of May 18-22)[cite: 220].
    * **Wrap-up:** Celebrate!
