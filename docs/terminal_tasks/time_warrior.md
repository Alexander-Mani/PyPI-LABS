# Thesis Workflow: Taskwarrior + Timewarrior Guide

## 1. Why this stack?
[cite_start]Your Final Project requires detailed time tracking (~400 hours total)[cite: 305]. [cite_start]You must present these hours at every Sitrep meeting[cite: 199].
* **Taskwarrior:** Manages *what* you need to do (The Schedule).
* **Timewarrior:** Manages *when* you did it (The Timesheet).

## 2. Installation & Setup

### Step A: Install
'''bash
# MacOS
brew install task timewarrior

# Linux (Debian/Ubuntu/Proxmox VM)
sudo apt-get install taskwarrior timewarrior
'''

### Step B: The "Hook" (Crucial)
You need to connect them so starting a task automatically starts the timer.

'''bash
# 1. Create the extensions directory if it doesn't exist
mkdir -p ~/.task/hooks

# 2. Copy the hook script (location varies by OS, check man page if not found)
# On standard Linux:
cp /usr/share/doc/task/scripts/hooks/on-modify.timewarrior ~/.task/hooks/
chmod +x ~/.task/hooks/on-modify.timewarrior

# On MacOS (Homebrew):
cp $(brew --prefix task)/share/doc/task/scripts/hooks/on-modify.timewarrior ~/.task/hooks/
chmod +x ~/.task/hooks/on-modify.timewarrior
'''

### Step C: Configuration
Configure Timewarrior to handle the specific reporting needs of your Thesis.

'''bash
# Set up a specific confirmation so you don't accidentally leave timers running
task config confirmation on
'''

## 3. Daily Workflow

This is the loop you will use every time you sit down at Frostbyte or work from home.

### 1. Start Working
When you sit down, list your tasks and pick one.

'''bash
# List tasks for Phase I
task project:Thesis phase:I list

# Start a specific task (e.g., ID 1)
task 1 start
'''
*Result:* Task 1 is marked "Active", and Timewarrior starts a clock tagged with "Thesis" and the specific task description.

### 2. Stop Working (Break/End of Day)
'''bash
task 1 stop
'''
*Result:* The timer stops. The time is logged to the database.

### 3. Adjusting Time (Forgot to track?)
If you worked for 2 hours on "Research" but forgot to run the command:

'''bash
timew track :yesterday 14:00 - 16:00 Thesis Research
'''

## 4. Reporting for Sitreps

[cite_start]You need to show "Unnir tímar" (Worked hours) broken down by category (Design, Dev, Writing)[cite: 170].

### View Summary for the Week
'''bash
timew summary :week
'''

### View Total Project Hours (For the "400 Hour" Goal)
'''bash
timew summary :all tag:Thesis
'''

### Exporting for the Report
You can pipe this output to a file to include in your LaTeX/Overleaf report.
'''bash
timew summary :month > january_report.txt
'''

## 5. Pro-Tips for this Project

* **Tags are key:** The import script tags everything with `Thesis`. It also adds `Phase_I`, `Phase_II`, etc. Use filters: `task +Phase_I list`.
* **Burndown:** You can see how many tasks are left vs. completed.
    '''bash
    task burndown
    '''
* **Contexts:** If you are purely writing, hide the coding tasks:
    '''bash
    task context define writing project:Thesis +writing
    task context writing
    # Now you only see writing tasks
    task context none
    # Now you see everything
    '''
