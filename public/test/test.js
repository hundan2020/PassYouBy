// 通用多线程调用函数
let doWorker = function([func_name, param]) {
	let worker1 = new Worker('./test.js');
	let worker2 = new Worker('./test.js');
	let time;
	time = new Date();
    worker1.postMessage([func_name, param]);
    // worker2.postMessage('start');
	worker1.onmessage = function (messageEvent) {
		return messageEvent.data;
        // console.log('计算结束，结果为' + messageEvent.data + '，用时' + (new Date() - time) + 'ms');
    }
    // worker2.onmessage = function (messageEvent) {
    //     console.log('计算结束，结果为' + messageEvent.data + '，用时' + (new Date() - time) + 'ms');
    // }
}

onmessage = function (messageEvent) {
	// postMessage(f);
	let result = eval(messageEvent.data[0] + '(' + messageEvent.data[1] + ')');
	postMessage(result);
 //    switch (messageEvent.data) {
 //        case 'start':
 //            let result = fabonacci(43);
 //            postMessage(result);
	// }
}

let fun1 = function(n) {
    if (n === 0) {
        return 0;
    }
    if (n === 1) {
        return 1;
    }
    return fun1(n - 1) + fun1(n - 2);
}