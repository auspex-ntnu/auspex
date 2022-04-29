from pylatex import escape_latex, NoEscape


def hyperlink(url, text):
    text = escape_latex(text)
    return NoEscape(r"\href{" + url + "}{" + text + "}")
