source /home/ubuntu/pwndbg/gdbinit.py
source /home/ubuntu/splitmind/gdbinit.py

set context-clear-screen on
set follow-fork-mode parent
set show-flags on

python
import splitmind
(splitmind.Mind()
  .tell_splitter(show_titles=True)
  .tell_splitter(set_title="Main")
  .right(display="backtrace", size="25%")
  .above(of="main", display="disasm", size="80%", banner="top")
  .right(cmd='tty; tail -f /dev/null', size="50%", clearing=False)
  .tell_splitter(set_title='Input / Output')
  .above(display="stack", size="100%")
  .above(display="legend", size="25")
  .show("regs", on="legend")
  .below(of="backtrace", cmd="ipython", size="50%")
  .below(of="backtrace", display="code", size="50%")
).build(nobanner=True)
end
set context-code-lines 30
set context-source-code-lines 10
set context-stack-lines 20
set context-sections  "regs args code disasm stack backtrace"

