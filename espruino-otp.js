// подключаем реализацию SHA1 из библиотеки jsSHA
// код модуля по данной ссылке уже минифицирован
const jsSHA = require('https://raw.githubusercontent.com/Caligatio/jsSHA/master/src/sha1.js');

// подключаем модуль HID клавиатуры
const kb = require('USBKeyboard');

// модули hmac и crypto
const hmac = require('hmac');
const crypto = require('crypto');


/**
 * Функция перевода строки в кодировке Base-32 в строку шестнадцатиричных цифр
 *
 * @param {string} base32    - входная строка в кодировке Base-32
 * @returns {string}         - Результат в виде строки шестнадцатиричных цифр
 */
const base32ToHex = function(base32) {
  const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = ""; // последовательность бит
  let hex  = ""; // результирующая строка шестнадцатиричных цифр
  // преобразуем последовательность символов в строку двоичных цифр
  for (let i = 0; i < base32.length; i++) {
    // текущий символ закодированной строки
    const ch = base32.charAt(i).toUpperCase();
    // значение 0..31, соответствующее символу Base-32
    const val = base32chars.indexOf(ch);
    // добавляем биты полученного числа в строку двоичных цифр
    bits += decToBin(val, 5);
  }
  // преобразуем строку двоичных цифр в строку шестнадцатиричных цифр
  for (let i = 0; i + 4 <= bits.length; i+=4) {
    // выделяем 4 бита, соответствующие одной шестнадцатиричной цифре
    const chunk = bits.substr(i, 4);
    // преобразуем 4 бита в 1 шестнадцатиричную цифру
    // и накапливаем в результирующей строке
    hex = hex + parseInt(chunk, 2).toString(16);
  }
  return hex;
};

/**
 * Вспомогательная функция дополнения строки до заданного количества символов
 *
 * @param {string} s - исходная строка
 * @param {number} l - необходимая длина строки, до которой осуществялется дополнение
 * @param {string} p - символ-заполнитель
 * @returns {string} - результирующая строка
 */
const leftpad = function(s, l, p) {
  while (s.length < l) s = p + s; // дополняем слева до достижения нужной длины
  return s;
};

/**
 * Преобразование числа в строку шестнадцатиричных цифр
 *
 * @param {number} num       - исходное число
 * @param {string} [byteLen] - длина результирующего слова в _байтах_ (если результат меньше,
 *                             он будет дополнен до этого значения)
 */
const decToHex = function(num, byteLen) {
  // преобразуем десятичное число в строку шестнадцатиричных цифр
  let res = Math.round(num).toString(16);
  // дополняем нулями
  return leftpad(res, (byteLen || 1)*2, "0");
};

/**
 * Преобразование строки шестнадцатиричных цифр в число
 *
 * @param {string} strHex - строка шестнадцатиричных цифр
 * @returns {number}      - результирующее число
 */
const hexToDec = function(strHex) {
  return parseInt(strHex, 16);
};

/**
 * Преобразование числа в строку двоичных цифр
 *
 * @param   {number} num    - исходное число
 * @param   {number} bitLen - количество бит в результате
 * @returns {string}        - строка двоичных цифр
 */
const decToBin = function(num, bitLen) {
  // преобразуем десятичное число в строку шестнадцатиричных цифр
  // дополняем нулями
  return leftpad(num.toString(2), bitLen, '0');
};

// Класс для вычисления SHA1 с использованием crypto.SHA1() для использования модулем `hmac`
const sha1 = function(m) {

  const self = {}; // инициализируем результирующий объект

  // сохраняем параметр конструктора в self._message
  self._message = m || '';
  self.block_size = 64;

  // функция `update` просто добавляет новую строку к self._message
  self.update = function(m) {
    self._message += m;
  };

  // вычисление дайджеста от self._message
  self.digest = function() {
    const digestArrayBuffer = crypto.SHA1(self._message);
    let s = arrBufToStr( digestArrayBuffer );
    return s;
  };

  // не используется в библиотеке `hashlib`
  self.hexdigest = function() {
    throw new Error('Not implemented');
  };

  return self;
};

/**
 * Преобразование объекта ArrayBuffer в строку
 *
 * @param {ArrayBuffer} a
 * @returns {string}
 */
const arrBufToStr = function(a) {
  let s = "";
  for (let i = 0; i < a.length; i++)
    s += String.fromCharCode( a[i] );
  return s;
};

/**
 * Функция перевода символов строки байт в их шестнадцатиричное представление
 * в виде строки шестнадцатиричных цифр
 *
 * @param {string} str
 * @returns {string}
 */
const strToHex = function(str) {
  let s = "";
  for (let i = 0; i < str.length; i++)
    s += (256+str.charCodeAt(i)).toString(16).substr(-2);
  return s;
};

/**
 * Функция перевода строки шестнадцатиричных цифр в строку байт
 *
 * @param {string} str
 * @returns {string}
 */
const hexToStr = function(str) {
  let s = "";
  for (let i = str.length-1; i>0; i-=2) {
    const byte = str.substr(i-1,2);
    s = String.fromCharCode( hexToDec(byte) ) + s;
  }
  return s;
};


TOTP = function() {

  /**
   * Функция вычисления счетчика на основе текущего времени
   *
   * @returns {string}           - Результат в виде строки шестнадцатиричных цифр
   */
  this.calcCounter = function() {
    // текущее время в секундах
    const currentTimeSec = Math.round(new Date().getTime() / 1000.0);
    // начало отсчёта
    const startTimeSecT0 = 0;
    // длительность интервала
    const intervalSecTI = 30;
    // текущее значение счётчика
    const counterTC = Math.floor( (currentTimeSec-startTimeSecT0)/intervalSecTI);
    // время начала следующего интервала (т.е. момент, когда текущий код перестанет быть валиден)
    const nextIntervalSec = (counterTC+1) * intervalSecTI;
    // оставшееся время валидности текущего кода
    this.validFor = nextIntervalSec - currentTimeSec;
    // преобразуем значение счетчика в строку шестнадцатиричных цифр, соответствующую 8 байтам
    const counterHex = decToHex(counterTC, 8);
    return counterHex;
  };

  /**
   * Функция вычисления HMAC для SHA1 с использованием библиотеки jsSHA
   *
   * @param {string} secretHex   - Значение secret в виде строки шестнадцатиричных цифр
   * @param {string} messageHex  - Значение message в виде строки шестнадцатиричных цифр
   * @returns {string}           - Результат в виде строки шестнадцатиричных цифр
   */
  this.hmacSha1 = function (secretHex, messageHex) {
    // создаем объект для вычисления HMAC SHA1
    const shaObj = new jsSHA("SHA-1", "HEX");
    shaObj.setHMACKey(secretHex, "HEX"); // задаем secret
    shaObj.update(messageHex);           // задаем строку
    return shaObj.getHMAC("HEX");        // возвращаем полученное значение HMAC
  };

  this.dynamicTruncate = function(hmacHex) {
    // в качестве смещения берем последний полубайт (то есть последний символ строки)
    const offset = hexToDec(hmacHex.substring(hmacHex.length - 1));
    // выделяем 4 байта, начиная с полученного смещения
    const truncatedHex = hmacHex.substr(offset * 2, 8);
    // выделяем младшие 31 бит
    const truncatedDec = (hexToDec(truncatedHex) & hexToDec("7fffffff")) + "";
    return decToHex(truncatedDec);
  };

  this.generateHotp = function(secretHex, counterHex, len) {
    // по умолчанию длина OTP-пароля 6 цифр
    len = len || 6;
    // функция вычисления HMAC SHA1 с использованием библиотеки jsSHA
    //const hmacHex = this.hmacSha1(secretHex, counterHex);
    const hmacHex = this.hmacSha1_new(secretHex, counterHex);    // производим динамическое отсчечение
    const trunc_hex = this.dynamicTruncate(hmacHex);
    // преобразуем в строку десятичных цифр 
    const trunc_dec = hexToDec(trunc_hex) + '';
    // возвращаем последние цифры
    return trunc_dec.substr(trunc_dec.length - len, len);
  };

  this.getOTP = function(secret) {
    console.log('* Calculating OTP...');
    // Гасим красный светодиод
    digitalWrite(LED1, false);
    // Включаем мерцание зеленого светодиода
    analogWrite(LED2, 0.01, { soft: true, freq: 16 });
    // Сохраняем текущее время
    const startTime = new Date();
    try {
      // вычисляем значение счетчика
      const counterHex = this.calcCounter();
      console.log(`** counterHex: ${counterHex}`);
      // переводим секретный ключ из Base-32 в строку шестнадцатиричных цифр
      const secretHex = base32ToHex(secret);
      console.log(`* secretHex: ${secretHex}`);
      // Вычисляем одноразовый пароль
      const otp = this.generateHotp(secretHex, counterHex);
      console.log(`* DONE, OTP: ${otp} [${ Math.round(new Date() - startTime)/1000} seconds]`);
      // индицируем завершение вычислений выключением зеленого светодиода
      digitalWrite(LED2, false);
      return otp; // возвращаем результат

    } catch (error) {
      // в случае ошибки
      // гасим зеленый светодиод
      digitalWrite(LED2, false);
      // индицируем ошибку мерцанием красного светодиода
      analogWrite(LED1, 1, { soft: true, freq: 5 });
      console.log('* ERROR:', error);
      // прерываем выполнение с выводом ошибки
      throw error;
    }
  };

  this.hmacSha1_new = function (secretHex, messageHex) {
    // преобразуем параметры в нужный вид
    const secretStr  = hexToStr(secretHex);
    const messageStr = hexToStr(messageHex);
    // вычисляем HMAC с помощью встроенной функции, передав ей секретный ключ, сообщение 
    // и наш объект-"обёртку" вокруг `crypto.SHA1`
    const shaObj = hmac.create(secretStr, messageStr, sha1);
    return shaObj.hexdigest();  // возвращаем полученное значение HMAC
  };

};


const totpObj = new TOTP();


setWatch(
  // callback при нажатии на кнопку
  function() {
    // гасим все светодиоды
    digitalWrite(LED1, false);
    digitalWrite(LED2, false);

    // начальные значения:
    // - пин-код (если есть)
    const pin = ""; // put_your_PIN_Prefix_here
    // - секретный постоянный пароль для генерации одноразовых паролей
    const secretBase32 = "ABCDEFGHIJKLMNOP"; // put_your_google_authenticator_secret_here
    // !!!
    // в данной реализации секретный пароль хранится в памяти Espruino в открытом виде
    // и может быть без проблем считан злоумышленником
    // !!!
    // вычисляем одноразовый пароль
    const otp = totpObj.getOTP(secretBase32);
    // включаем зеленый свтодиод на полную яркость
    digitalWrite(LED2, true);
    // имитируем набор на клавиатуре символов пин-кода и одноразового пароля
    kb.type(pin + otp, function() {
      // по завершении набора символов имитируем нажатие клавиши `ENTER`
      kb.tap(kb.KEY.ENTER);
      // гасим зеленый светодиод
      digitalWrite(LED2, false);
    });
  },
  // мониторим изменение порта, к которому подключена встроенная кнопка
  BTN,
  // параметры мониторинга 
  {
    debounce: 100, //
    repeat: true,  //
    edge: "rising" //
  }
);

