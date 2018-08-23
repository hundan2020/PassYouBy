let fun1 = function(n) {
    if (n === 0) {
        return 0;
    }
    if (n === 1) {
        return 1;
    }
    return fun1(n - 1) + fun1(n - 2);
}

let fun2 = function(n) {
    if (n === 0) {
        return 0;
    }
    if (n === 1) {
        return 1;
    }
    return fun2(n - 1) + fun2(n - 2);
}

