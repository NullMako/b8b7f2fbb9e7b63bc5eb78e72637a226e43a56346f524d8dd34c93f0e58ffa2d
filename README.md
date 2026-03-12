# Практичний аналіз шкідливого PowerShell скрипта.

* Тип загрози: Stealer
* Джерело: MalwareBazaar
* Вперше виявлено: 2026-03-09 18:22:02 UTC
* Мова: PowerShell
* Розмір: 1,540,955 байт
* SHA-256: `b8b7f2fbb9e7b63bc5eb78e72637a226e43a56346f524d8dd34c93f0e58ffa2d`
* Розширення: `.ps1`

Сьогодні на розбір я завантажив шкідливий PowerShell скрипт. Хотілось би спочатку спробувати проаналізувати цей файл за допомогою VirusTotal:  

<img width="1319" height="838" alt="image" src="https://github.com/user-attachments/assets/4553d11e-aa7b-4a2c-8c1a-20e4fe3a6eee" />

Ну, є два варіанти: або це не шкідливий файл, або шкідливий код дуже гарно ховається. Тим паче, що навіть цих 2 антивіруси не бачать сигнатури.

## Розшифрування скрипта
Як ми бачимо на скріншоті цей скрипт є зашифрованим алгоритмом XOR та поверх цього закодований Base64
<img width="426" height="304" alt="image" src="https://github.com/user-attachments/assets/041c6304-8d94-42f0-bd15-20fbdf6ded65" />  
(23 тисячі стрічок зашифрованого коду)  
<img width="438" height="440" alt="image" src="https://github.com/user-attachments/assets/3328702f-ecf5-450d-9ec9-563274bc91ab" />  
<img width="684" height="704" alt="image" src="https://github.com/user-attachments/assets/de08145d-4739-46e6-be0e-20c056a78c2c" />

Якщо ми прогротаємо до самого кінця, ми побачимо функції `$base64reconstruction`, `$xorrotational`, `$masterdecoder` та `$executionhandler`. Якщо заглибитись у код, стають зрозумілими призначення цих функцій:

* `$base64reconstruction` - першим ділом йде ця функція. Вона знімає Base64 кодування.
* `$xorrotational` - згодом йде ця функція. Вона знімає XOR шифрування. Після виконання цієї функції, код приймає нативний вигляд.
* `$masterdecoder` - Ця функція викликає дві попередні функції та передає чистий код у `$executionhandler`.
* `$executionhandler` - Запуск коду.

Потрібно розшифрувати шкідливий код. Але навіщо це робити руками, якщо сам скрипт це може зробити замість нас? Перепишемо функцію `$executionhandler` - замість команд виконання вставляємо цю команду:  
`$decodedScript | Out-File "C:\Users\USER\Desktop\decoded_script.ps1"`  

<img width="746" height="448" alt="image" src="https://github.com/user-attachments/assets/dd254721-502d-41eb-ba94-63e8176bf3c6" />
<img width="860" height="674" alt="image" src="https://github.com/user-attachments/assets/a7d85ffe-46b3-4058-a0a0-4146e3539e52" />

## Отримання пейлоаду
І вуаля. Тут ми бачимо нескінченний цикл, що перевіряє наявність процесу `Aspnet_compiler.exe`. Але це, поки що, нас не так цікавить, як змінні `$assemblyData` та `$ExecutionPayload`.  

Почнемо з `$assemblyData`. Видно що цей рядок закодований Base64. За допомогою утиліти CyberChef декодуємо. Перші два байти (M Z) вказують на те, що це виконуваний файл Windows. Зберігаємо файл у вигляді тектового документа(ми ще не знаємо справжнього розширення).  

Перейдемо до другого. З нам набагато простіше. Ми бачимо величезний набір цифр, але перших два, все ще вказують на виконувальний файл Windows. Створимо простий PowerShell скрипт і запишемо в нього лише 2 рядки:  

```powershell
[Byte[]]$ExecutionPayload = (77,90,144,0...0,0,0)  
[System.IO.File]::WriteAllBytes("C:\Users\[КОРИСТУВАЧ]\Desktop\payload.txt", $ExecutionPayload)
```

В результаті ми отримали два файли. Час їх проаналізувати.

## Аналіз файлів
<img width="774" height="439" alt="image" src="https://github.com/user-attachments/assets/885886f2-5f15-4279-8a2a-ad840962251f" />
<img width="771" height="436" alt="image" src="https://github.com/user-attachments/assets/9316cbd9-ed8b-4a3a-a1a9-fc02406f5ef3" />

Переходимо у утиліту `Detect it Easy` та скануємо обидва файли. І тут починаються проблеми. Перший файл - це `.dll` бібліотека написана на C#, хоч і обфускована. Другий - це швидше за все корисне навантаження написане на C++, але під захистом VMProtect.  

Почнемо з легшого, а саме з `.dll` бібліотеки. Запускаємо утиліту `NETReactorSlayer` та молимось, щоб обфускація була не супер складною. Проводимо повторний аналіз в `Detect it Easy`.  
<img width="771" height="438" alt="image" src="https://github.com/user-attachments/assets/06ab2d90-779b-4262-b261-8970a6ee579a" />

І о чудо. Файл успішно деобфускований(зверніть увагу на розміри файлу що був, та яким став). Відкриваємо код у `dnSpy`. Що ж ми там будемо шукати? Подивіться уважніше на код розшифрованого PowerShell скрипта. Він з якоюсь метою шукав у класі `DEV.DOWN` метод `SHOOT`. Дивимось туди. 

<img width="927" height="710" alt="image" src="https://github.com/user-attachments/assets/2616236a-0f3b-494b-9447-28d26e17b9fd" />
<img width="669" height="693" alt="image" src="https://github.com/user-attachments/assets/685710fb-87b8-425d-9cee-742c947b1b7d" />

**А тепер про цю функцію:** Вона реалізує класичну техніку Process Hollowing. Для обходу статичного аналізу всі виклики Windows API приховані за динамічними делегатами. Алгоритм працює так: спочатку функція створює легітимний "зомбі-процес" (в нашому випадку `Aspnet_compiler.exe`) у призупиненому стані (`CREATE_SUSPENDED`). Далі за допомогою `NtUnmapViewOfSection` пам'ять процесу очищається від оригінального коду, а замість нього через `VirtualAllocEx` та `WriteProcessMemory` посекційно записується наш розшифрований пейлоад. Наприкінці інжектор оновлює точку входу в регістрах потоку і викликає `ResumeThread`, запускаючи шкідливий код під маскою довіреного системного файлу.  

На рахунок другого файлу(пейлоада). Спробуймо просканувати популярним інструментом VirusTolal.
<img width="1061" height="910" alt="image" src="https://github.com/user-attachments/assets/96bbc5ad-df54-4918-a16a-6c0167cd7895" />

VirusTotal вказує на те, що це стілер з сигнатурою Formbook. Бібліотека, яку ми щойно розбирали, інжектить цей пейлоад у процес `Aspnet_compiler.exe`. Через протектор не вдалось отримати ні відкритий код, ні дамп працюючого процесу. Якщо щось вдастся, обов'язково напишу.

## YARA правило

Наразі моя детект сигнатура виглядає так:

```yara
rule PS_Formbook_Loader_Mar2026 {
    meta:
        description = "Detects obfuscated PowerShell loader used to inject Formbook"
        author = "NullMako"
        date = "2026-03-10"
        hash = "b8b7f2fbb9e7b63bc5eb78e72637a226e43a56346f524d8dd34c93f0e58ffa2d"
        threat_type = "Stealer"

    strings:
        $func1 = "$base64reconstruction" ascii wide nocase
        $func2 = "$xorrotational" ascii wide nocase
        $func3 = "$masterdecoder" ascii wide nocase
        $func4 = "$executionhandler" ascii wide nocase

        $xor_key = "DeOF5nMlMwq0ya57s8N3hONJnXvJLq3HQd0fzw+dmdQ=" ascii wide

        $inj1 = "DEV.DOWN" ascii wide
        $inj2 = "SHOOT" ascii wide
        $inj3 = "Aspnet_compiler.exe" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            (3 of ($func*) and $xor_key)
            or
            // Або спрацює, якщо знайдено всі індикатори ін'єкції (Stage 2 розшифрований)
            (all of ($inj*))
        )
}
```

## Висновки
Ось висновки на рахунок даного скрипта:
| Тип | Індикатор | Опис |
| :--- | :--- | :--- |
| **SHA256** | `b8b7f2fbb9e7b63bc5eb78e72637a226e43a56346f524d8dd34c93f0e58ffa2d` | Оригінальний PowerShell контейнер |
| **Process** | `Aspnet_compiler.exe` | Легітимний процес, який використовується для Process Hollowing |
| **Malware Family** | Formbook | Фінальне корисне навантаження (Stealer) |
