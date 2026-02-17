import os
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt


class TuiMethods:
    @staticmethod
    def clear_screen():
        """Clears the terminal screen."""
        os.system("cls" if os.name == "nt" else "clear")

    @staticmethod
    def load_menu_panel(title, menu_items: dict):
        """Creates the menu panel using rich."""
        if not menu_items:
            raise ValueError("No items in dict")

        menu_text = Text(justify="left")
        option_set = set()
        for index, (key, value) in enumerate(menu_items.items()):
            is_last_pair = index == len(menu_items) - 1

            phrase, style = next(iter(value.items()))

            menu_item = f"{key.upper()}. {phrase}\n"
            if is_last_pair:
                menu_item = f"{key.upper()}. {phrase}"

            menu_text.append(menu_item, style=style)
            option_set.add(str(key))

        main_menu_panel = Panel(
            menu_text,
            title=f"[bold cyan]{title}[/bold cyan]",
            subtitle="[default]Enter a symbol to select[/default]",
            border_style="cyan",
        )
        console = Console()

        # clear_screen()
        console.print(main_menu_panel)

        choice = ""
        while choice not in option_set:
            choice = Prompt.ask("[cyan] [SYMBOL][/cyan]")
            if choice.isalpha():
                if choice.lower() in option_set: return choice.lower
                elif choice.upper() in option_set: return choice.upper()

        # clear_screen()
        return choice.lower()

    @staticmethod
    def input_int_in_range(n_min: int, n_max: int) -> int:
        while True:
            user_input = input(f"Please enter a number between {n_min} and {n_max}: ")
            try:
                number = int(user_input)
            except ValueError:
                print("Invalid input. Please enter a whole number.")
                continue
            if n_min <= number <= n_max:
                return number
            else:
                print(f"Error: The number must be between {n_min} and {n_max}.")

    @staticmethod
    def print_article_overview(author_website: str, article: dict):
        """
        Prints the scraped and processed article content in a readable format using rich.
        """
        console = Console()

        display_text = Text()
        display_text.append("Date: ", style="bold magenta")
        display_text.append(f"{str(article.get('date', 'N/A'))}\n")
        display_text.append("URL: ", style="bold magenta")
        display_text.append(f"{article.get('url', 'N/A')}\n\n", style="underline blue")
        display_text.append("Summary:\n", style="bold green")
        display_text.append(article.get("sumy_summary", "No summary available."))

        summary_panel = Panel(
            display_text,
            subtitle=f"[bold cyan]{author_website}[/bold cyan]",
            title=f"[bold blue]{article.get('title', 'No Title')}[/bold blue]",
            border_style="blue",
        )
        console.print(summary_panel)

    @staticmethod
    def prompt_validated_word(title: str) -> str:
        """
        Gets a tag from the user, validates it to ensure:
        - It is a single word (no spaces)
        - It is not too long (max 20 characters)
        - Returns it in ALL CAPS
        """
        console = Console()

        display_text = Text()
        display_text.append(f"{title}\n", style="bold green")

        panel = Panel(display_text, border_style="blue")
        console.print(panel)

        while True:
            word = console.input("[bold cyan]Enter a single word:[/bold cyan] ").strip()

            if " " in word:
                console.print(
                    "[red]Error:[/red] Input must be a single word without spaces."
                )
                continue
            if len(word) == 0:
                console.print("[red]Error:[/red] Input cannot be empty.")
                continue
            if len(word) > 20:
                console.print("[red]Error:[/red] Input too long (max 20 characters).")
                continue

            return word.upper()

