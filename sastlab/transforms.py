"""Canonical subset DAG: every candidate is rebuilt from its original seed."""
import ast
import copy

# Core operators move the same value around. Flow-breaking operators try to make
# the value reach the sink through a path static taint tracking may not follow; they keep
# behavior for every string input except where stated. New operators are appended so existing
# mask numbers keep their meaning.
CORE_OPERATORS = (
    "rename", "format_swap", "literal_slice", "dead_padding",
    "extract_1", "extract_2", "branch_split", "dict_dispatch",
)
FLOW_OPERATORS = (
    "dynamic_sink",     # cursor.execute -> getattr(cursor, "exe" + "cute"): sink name built at run time
    "char_launder",     # user_id = "".join(chr(ord(c)) for c in user_id): identity, passes through int
    "deep_nest",        # value boxed in eight nested lists and unboxed again
    "db_roundtrip",     # value stored in and read back from a private in-memory SQLite table
    "queue_roundtrip",  # value passed through queue.Queue
    "simplequeue_roundtrip",  # value passed through queue.SimpleQueue (a different stdlib container)
    "pickle_roundtrip",       # value serialized and deserialized with pickle
)
# Sink-resolution operators: the call to cursor.execute is made through a library indirection.
SINK_OPERATORS = (
    "partial_sink",       # functools.partial(cursor.execute)(query)
    "methodcaller_sink",  # operator.methodcaller("execute", query)(cursor)
    "unbound_sink",       # type(cursor).execute(cursor, query)
)
OPERATORS = CORE_OPERATORS + FLOW_OPERATORS + SINK_OPERATORS
# Which part of a taint analysis each operator stresses (domain-specific rationale; see docs/methodology.md).
# "control" operators leave the source-to-sink flow graph unchanged and serve as a baseline.
TAXONOMY = {
    "rename": "control", "format_swap": "control", "literal_slice": "control", "dead_padding": "control",
    "extract_1": "interprocedural", "extract_2": "interprocedural", "branch_split": "control-flow",
    "dict_dispatch": "sink-resolution", "dynamic_sink": "sink-resolution", "partial_sink": "sink-resolution",
    "methodcaller_sink": "sink-resolution", "unbound_sink": "sink-resolution",
    "char_launder": "value-propagation", "pickle_roundtrip": "value-propagation",
    "deep_nest": "container", "queue_roundtrip": "container", "simplequeue_roundtrip": "container",
    "db_roundtrip": "second-order-storage",
}
OPERATOR_HELP = {
    "rename": "rename local names", "format_swap": "f-string to str.format or join",
    "literal_slice": "split SQL string literals", "dead_padding": "add an unreachable branch",
    "extract_1": "move query building into one helper function", "extract_2": "move it through two helper functions",
    "branch_split": "duplicate the query assignment into if/else",
    "dict_dispatch": "call execute through a dict lookup",
    "dynamic_sink": "call execute via getattr with a computed name",
    "char_launder": "rebuild the input string character by character via chr(ord(c))",
    "deep_nest": "box the input in nested lists and unbox it",
    "db_roundtrip": "store the input in a private SQLite table and read it back",
    "queue_roundtrip": "pass the input through queue.Queue",
    "simplequeue_roundtrip": "pass the input through queue.SimpleQueue",
    "pickle_roundtrip": "serialize and deserialize the input with pickle",
    "partial_sink": "call execute through functools.partial",
    "methodcaller_sink": "call execute through operator.methodcaller",
    "unbound_sink": "call execute as an unbound method of the cursor's type",
}
# Calls the sink-resolution operators rewrite: a database `.execute` (SQL injection seeds) and the `subprocess` entry points
# (command injection seeds). The entry function keeps the name get_user_profile and its two parameters for every class.
SINK_NAMES = ("execute", "check_output", "run", "call", "check_call", "popen", "Popen", "getoutput")
# Sinks that are plain names (path traversal seeds): the builtin `open`. `getattr`, `partial` and a dict can hide them; there is no receiver, so
# methodcaller_sink and unbound_sink do not apply.
SINK_FUNCTIONS = ("open",)


def is_sink_call(node):
    f = node.func
    return (isinstance(f, ast.Attribute) and f.attr in SINK_NAMES) or (isinstance(f, ast.Name) and f.id in SINK_FUNCTIONS)
ASSIGNMENT_OPERATORS = ("rename", "format_swap", "literal_slice", "dead_padding",
                        "extract_1", "extract_2", "branch_split")


def entry(tree):
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "get_user_profile"]
    if len(functions) != 1:
        raise ValueError("Seed must define get_user_profile(db_conn, user_id)")
    return functions[0]


def query_assignment(fn):
    # Locate the assignment feeding a DB execute call, independent of variable names.
    names = [n.args[0].id for n in ast.walk(fn) if isinstance(n, ast.Call)
             and is_sink_call(n) and n.args and isinstance(n.args[0], ast.Name)]
    for stmt in fn.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            if stmt.targets[0].id in names:
                return stmt
    raise ValueError("Seed needs a top-level query assignment feeding the sink call, e.g. .execute(query)")


COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def free_names(node, bound=frozenset()):
    """Names read in node, without the variables of comprehensions and lambdas inside it (those are local to them)."""
    if isinstance(node, COMPREHENSIONS):
        names, inner = set(), set(bound)
        for generator in node.generators:
            names |= free_names(generator.iter, inner)  # the first iterable is evaluated in the enclosing scope
            inner |= {n.id for n in ast.walk(generator.target) if isinstance(n, ast.Name)}
            for condition in generator.ifs:
                names |= free_names(condition, inner)
        for part in ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]):
            names |= free_names(part, inner)
        return names
    if isinstance(node, ast.Lambda):
        args = node.args
        params = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs} | {a.arg for a in (args.vararg, args.kwarg) if a}
        return set().union(*(free_names(d, bound) for d in args.defaults + [d for d in args.kw_defaults if d]),
                           free_names(node.body, set(bound) | params))
    if isinstance(node, ast.Name):
        return {node.id} if isinstance(node.ctx, ast.Load) and node.id not in bound else set()
    return set().union(*(free_names(child, bound) for child in ast.iter_child_nodes(node)))


def names_in(expr):
    return sorted(free_names(expr))


def scope_stores(fn):
    """Names assigned in the function's own scope. The target variables of a comprehension are local to it, so they are
    skipped; its iterables and conditions belong to the function."""
    names = set()

    def visit(node):
        if isinstance(node, ast.comprehension):
            for part in [node.iter] + node.ifs:
                visit(part)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        for child in ast.iter_child_nodes(node):
            visit(child)
    visit(fn)
    return names


class Rename(ast.NodeTransformer):
    """Renames the function's locals everywhere and a comprehension's variables only inside that comprehension, so a
    global that shares a name with a comprehension variable keeps its name."""
    def __init__(self, mapping, local):
        self.mapping, self.local, self.scopes = mapping, local, []

    def new(self, name):
        if name in self.mapping and (name in self.local or any(name in s for s in self.scopes)):
            return self.mapping[name]
        return name

    def visit_Name(self, node):
        node.id = self.new(node.id)
        return node

    def visit_arg(self, node):
        node.arg = self.new(node.arg)
        return node

    def visit_ExceptHandler(self, node):
        if node.name:
            node.name = self.new(node.name)
        self.generic_visit(node)
        return node

    def visit_comprehension_scope(self, node):
        targets = set()
        for index, generator in enumerate(node.generators):
            self.scopes.append(set(targets) if index else set())  # the first iterable is evaluated outside
            generator.iter = self.visit(generator.iter)
            self.scopes.pop()
            targets |= {n.id for n in ast.walk(generator.target) if isinstance(n, ast.Name)}
            self.scopes.append(set(targets))
            generator.target = self.visit(generator.target)
            generator.ifs = [self.visit(c) for c in generator.ifs]
            self.scopes.pop()
        self.scopes.append(targets)
        if isinstance(node, ast.DictComp):
            node.key, node.value = self.visit(node.key), self.visit(node.value)
        else:
            node.elt = self.visit(node.elt)
        self.scopes.pop()
        return node

    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_comprehension_scope


def sink_statement(fn):
    # The first top-level statement of the entry function that contains a sink call (the anchor when no query assignment exists).
    for stmt in fn.body:
        if any(isinstance(n, ast.Call) and is_sink_call(n) for n in ast.walk(stmt)):
            return stmt
    raise ValueError("Seed has no sink call in the entry function")


def apply(tree, operator):
    fn = entry(tree)
    # rename needs no query assignment; dead_padding falls back to the statement that holds the sink call (seeds that build the
    # query inline, e.g. .execute(f"..."), have no assignment). The other operators rewrite the assigned expression.
    needs_assignment = operator in ASSIGNMENT_OPERATORS and operator not in ("rename", "dead_padding")
    assignment = query_assignment(fn) if needs_assignment else None
    if operator == "rename":
        if any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)) for s in fn.body for n in ast.walk(s)):
            raise ValueError("Nested scopes are outside the seed contract")
        handlers = {n.name for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler) and n.name}
        # the numbering covers every assigned name, comprehension variables included, as in the saved runs
        bound = sorted({n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
                       | {a.arg for a in fn.args.args} | handlers)
        Rename({n: f"_mt_local_{i}" for i, n in enumerate(bound)}, scope_stores(fn) | {a.arg for a in fn.args.args} | handlers).visit(fn)
    elif operator == "format_swap":
        expr = assignment.value
        if isinstance(expr, ast.JoinedStr):
            template, values = "", []
            for part in expr.values:
                if isinstance(part, ast.Constant):
                    template += part.value.replace("{", "{{").replace("}", "}}")
                elif isinstance(part, ast.FormattedValue) and part.format_spec is None:
                    conversion = "" if part.conversion == -1 else "!" + chr(part.conversion)
                    template += "{" + str(len(values)) + conversion + "}"
                    values.append(part.value)
                else:
                    raise ValueError("Format specifications are outside the seed contract")
            assignment.value = ast.Call(ast.Attribute(ast.Constant(template), "format", ast.Load()), values, [])
        elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            parts = []
            def flatten(n):
                if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                    flatten(n.left)
                    flatten(n.right)
                else:
                    parts.append(n)
            flatten(expr)
            assignment.value = ast.Call(ast.Attribute(ast.Constant(""), "join", ast.Load()), [ast.List(parts, ast.Load())], [])
        else:
            raise ValueError("format_swap supports f-strings or string concatenation")
    elif operator == "literal_slice":
        class Slice(ast.NodeTransformer):
            def visit_JoinedStr(self, node):
                # String literal nodes inside JoinedStr cannot become Subscript nodes.
                parts = [ast.FormattedValue(self.visit(n), -1, None) if isinstance(n, ast.Constant)
                         else self.visit(n) for n in node.values]
                return ast.JoinedStr(parts)

            def visit_Constant(self, node):
                if isinstance(node.value, str) and node.value:
                    return ast.Subscript(ast.Constant("#" + node.value), ast.Slice(ast.Constant(1), None, None), ast.Load())
                return node
        assignment.value = Slice().visit(assignment.value)
    elif operator == "dead_padding":
        try:
            anchor = query_assignment(fn)
        except ValueError:
            anchor = sink_statement(fn)
        fn.body.insert(fn.body.index(anchor), ast.parse("if False:\n    _mt_unused = 0").body[0])
    elif operator in ("extract_1", "extract_2"):
        count = 1 if operator == "extract_1" else 2
        expr = assignment.value
        # Pass only lexical locals; helper/global names remain globals.
        bound = {a.arg for a in fn.args.args} | scope_stores(fn)
        arguments = [n for n in names_in(expr) if n in bound]
        for hop in range(count):
            name = f"_mt_{operator}_{hop}"
            helper = ast.FunctionDef(name=name,
                args=ast.arguments(posonlyargs=[], args=[ast.arg(arg=n) for n in arguments],
                                   kwonlyargs=[], kw_defaults=[], defaults=[]),
                body=[ast.Return(expr)], decorator_list=[])
            tree.body.insert(tree.body.index(fn), helper)
            expr = ast.Call(ast.Name(name, ast.Load()), [ast.Name(n, ast.Load()) for n in arguments], [])
        assignment.value = expr
    elif operator == "branch_split":
        # Domain is strings. Both branches preserve the query expression exactly.
        condition = ast.Compare(ast.Name(fn.args.args[1].arg, ast.Load()), [ast.Eq()], [ast.Constant("1")])
        fn.body[fn.body.index(assignment)] = ast.If(condition, [copy.deepcopy(assignment)], [copy.deepcopy(assignment)])
    elif operator == "dict_dispatch":
        class Dispatch(ast.NodeTransformer):
            def visit_Call(self, node):
                self.generic_visit(node)
                if is_sink_call(node):
                    node.func = ast.Subscript(ast.Dict([ast.Constant("run")], [node.func]), ast.Constant("run"), ast.Load())
                return node
        Dispatch().visit(fn)
    elif operator == "dynamic_sink":
        used_builtins = []

        class Dynamic(ast.NodeTransformer):
            def visit_Call(self, node):
                self.generic_visit(node)
                f = node.func
                if isinstance(f, ast.Name) and f.id in SINK_FUNCTIONS:
                    half = len(f.id) // 2
                    name = ast.BinOp(ast.Constant(f.id[:half]), ast.Add(), ast.Constant(f.id[half:]))
                    node.func = ast.Call(ast.Name("getattr", ast.Load()), [ast.Name("_mt_builtins", ast.Load()), name], [])
                    used_builtins.append(node)
                return node

            def visit_Attribute(self, node):
                self.generic_visit(node)
                if node.attr in SINK_NAMES and isinstance(node.ctx, ast.Load):
                    half = len(node.attr) // 2
                    name = ast.BinOp(ast.Constant(node.attr[:half]), ast.Add(), ast.Constant(node.attr[half:]))
                    return ast.Call(ast.Name("getattr", ast.Load()), [node.value, name], [])
                return node
        Dynamic().visit(fn)
        if used_builtins:
            tree.body.insert(tree.body.index(fn), ast.parse("import builtins as _mt_builtins").body[0])
    elif operator in FLOW_OPERATORS:
        parameter = fn.args.args[1].arg
        module_level = {"db_roundtrip": "import sqlite3 as _mt_sqlite3",
                        "queue_roundtrip": "import queue as _mt_queue",
                        "simplequeue_roundtrip": "import queue as _mt_queue",
                        "pickle_roundtrip": "import pickle as _mt_pickle"}
        body = {
            "char_launder": f"{parameter} = ''.join(chr(ord(_mt_c)) for _mt_c in {parameter})",
            "deep_nest": f"_mt_box = {'[' * 8}{parameter}{']' * 8}\n{parameter} = _mt_box{'[0]' * 8}",
            "db_roundtrip": ("_mt_db = _mt_sqlite3.connect(':memory:')\n"
                             "_mt_db.execute('CREATE TABLE t (v TEXT)')\n"
                             f"_mt_db.execute('INSERT INTO t VALUES (?)', ({parameter},))\n"
                             f"{parameter} = _mt_db.execute('SELECT v FROM t').fetchone()[0]"),
            "queue_roundtrip": f"_mt_q = _mt_queue.Queue()\n_mt_q.put({parameter})\n{parameter} = _mt_q.get()",
            "simplequeue_roundtrip": f"_mt_sq = _mt_queue.SimpleQueue()\n_mt_sq.put({parameter})\n{parameter} = _mt_sq.get()",
            "pickle_roundtrip": f"{parameter} = _mt_pickle.loads(_mt_pickle.dumps({parameter}))",
        }[operator]
        if operator in module_level:
            tree.body.insert(tree.body.index(fn), ast.parse(module_level[operator]).body[0])
        docstring = bool(fn.body) and isinstance(fn.body[0], ast.Expr) and isinstance(fn.body[0].value, ast.Constant) \
            and isinstance(fn.body[0].value.value, str)
        fn.body[int(docstring):int(docstring)] = ast.parse(body).body  # after the docstring, which stays the docstring
    elif operator in SINK_OPERATORS:
        sites = []
        # Names bound by any import statement, at module level or inside a function (`from os import path` binds a module as well).
        modules = {(a.asname or a.name).split(".")[0] for s in ast.walk(tree) if isinstance(s, (ast.Import, ast.ImportFrom)) for a in s.names}

        class Sink(ast.NodeTransformer):
            def visit_Call(self, node):
                self.generic_visit(node)
                f = node.func
                if not is_sink_call(node):
                    return node
                sites.append(node)
                if operator == "partial_sink":
                    partial = ast.Call(ast.Attribute(ast.Name("_mt_functools", ast.Load()), "partial", ast.Load()), [f], [])
                    return ast.Call(partial, node.args, node.keywords)
                if isinstance(f, ast.Name):
                    raise ValueError(f"{operator}: {f.id} is a function, not a method")
                if not isinstance(f.value, ast.Name):  # the receiver is evaluated twice, so it must be a plain name
                    raise ValueError(f"{operator} needs a plain-name receiver for execute")
                if operator == "methodcaller_sink":
                    caller = ast.Call(ast.Attribute(ast.Name("_mt_operator", ast.Load()), "methodcaller", ast.Load()),
                                      [ast.Constant(f.attr)] + node.args, node.keywords)
                    return ast.Call(caller, [f.value], [])
                if f.value.id in modules:  # type(module).run is not the module function
                    raise ValueError(f"{operator}: the receiver is a module, not an object")
                unbound = ast.Attribute(ast.Call(ast.Name("type", ast.Load()), [f.value], []), f.attr, ast.Load())
                return ast.Call(unbound, [f.value] + node.args, node.keywords)
        Sink().visit(fn)
        if not sites:
            raise ValueError(f"{operator}: no direct execute call is left to rewrite")
        imports = {"partial_sink": "import functools as _mt_functools", "methodcaller_sink": "import operator as _mt_operator"}
        if operator in imports:
            tree.body.insert(tree.body.index(fn), ast.parse(imports[operator]).body[0])
    return tree


def candidate(source, mask):
    if type(mask) is not int or not 0 <= mask < 1 << len(OPERATORS):
        raise ValueError(f"Candidate mask must be an integer in [0, {(1 << len(OPERATORS)) - 1}]")
    tree = ast.parse(source)
    if any((isinstance(n, ast.Name) and n.id.startswith("_mt_")) or
           (isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name.startswith("_mt_")) or
           (isinstance(n, ast.arg) and n.arg.startswith("_mt_")) for n in ast.walk(tree)):
        raise ValueError("Seed uses reserved _mt_ names")
    for index, operator in enumerate(OPERATORS):
        if mask & (1 << index):
            tree = apply(tree, operator)
    ast.fix_missing_locations(tree)
    compile(tree, "<candidate>", "exec")
    return ast.unparse(tree) + "\n"


def available(mask, pool=None):
    """Only increasing operator indices: no permutation duplicates or cycles. `pool` optionally
    restricts the search to a subset of operator indices (a harder, sparser search space)."""
    return [i for i in range(mask.bit_length(), len(OPERATORS)) if pool is None or i in pool]


def sequence(mask):
    return [op for i, op in enumerate(OPERATORS) if mask & (1 << i)]


def syntax_distance(seed, mutant):
    """Normalized AST preorder sequence edit distance (insert/delete via LCS)."""
    def tokens(source):
        def walk(node):
            yield type(node).__name__
            for field, value in ast.iter_fields(node):
                if isinstance(value, ast.AST):
                    yield from walk(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, ast.AST):
                            yield from walk(item)
                elif value is not None:
                    yield f"{field}={value!r}"
        return list(walk(ast.parse(source)))
    left, right = tokens(seed), tokens(mutant)
    # Dynamic programming LCS, unlike SequenceMatcher this yields exact insert/delete distance.
    row = [0] * (len(right) + 1)
    for a in left:
        previous = 0
        for j, b in enumerate(right, 1):
            old = row[j]
            row[j] = previous + 1 if a == b else max(row[j], row[j - 1])
            previous = old
    return (len(left) + len(right) - 2 * row[-1]) / max(1, len(left) + len(right))


def call_depth(source):
    """Maximum reachable local call hops from the entry, excluding DB/library calls."""
    tree = ast.parse(source)
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    def depth(name, active):
        if name in active:
            return 0
        calls = [n.func.id for n in ast.walk(functions[name]) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id in functions]
        return max([0] + [1 + depth(c, active | {name}) for c in calls])
    return depth("get_user_profile", set())
