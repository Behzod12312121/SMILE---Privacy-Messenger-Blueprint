 <h2>Smile (Русский)</h2>
<p>Мессенджер со сквозным шифрованием. Сервер спроектирован так, чтобы быть бесполезным для того, кто его держит.</p>
<hr>
<h2 id="arhitektura" class="atx">Архитектура</h2>
<p>Два сервиса, которые должны держать <strong>два разных оператора</strong>. Если оператор один, релей не даёт ничего.</p>
<pre><code class="fenced-code-block">телефон ──HTTPS──▶ релей ──HTTPS──▶ шлюз
                  (видит IP,       (видит запрос,
                   не содержимое)   не видит IP)</code></pre>
<ul>
<li><strong>Шлюз (gateway)</strong> — хранит конверты и отдаёт их по корзинам. Открытый текст не видит никогда. Журнал обращений не ведёт.</li>
<li><strong>Релей (relay)</strong> — принимает блоб, запечатанный на ключ шлюза (HPKE), и пересылает его. Видит ваш адрес, но не содержимое.</li>
</ul>
<p>Ни одна половина по отдельности не связывает отправителя с получателем.</p>
<h3 id="nastrojka" class="atx">Настройка</h3>
<table>
<thead>
<tr>
<th></th>
<th>Шлюз</th>
<th>Релей</th>
</tr>
</thead>
<tbody><tr>
<td>Слушает</td>
<td><code>127.0.0.1:8443</code></td>
<td><code>127.0.0.1:8444</code></td>
</tr>
<tr>
<td>Публично</td>
<td><code>https://your-gateway.example</code></td>
<td><code>https://your-relay.example</code></td>
</tr>
<tr>
<td>Требует</td>
<td>TLS-прокси</td>
<td>TLS-прокси, <code>MG_GATEWAY_URL</code></td>
</tr>
</tbody></table>
<p>TLS должен завершаться на прокси впереди — приложение отказывается от незашифрованного соединения и доверяет только системному хранилищу сертификатов.</p>
<pre><code class="fenced-code-block">MG_BUCKET_SIZE=16        # аккаунтов на один почтовый ящик
MG_POW_DIFFICULTY=16     # работа на сообщение
MG_DB=/data/server.db</code></pre>
<p>Отключите журналы доступа на прокси. Запись о том, кто и когда подключался, — ровно те метаданные, ради отсутствия которых всё это построено.</p>
<hr>
<h2 id="shifrovanie" class="atx">Шифрование</h2>
<p>libsignal — та же библиотека, что у Signal.</p>
<ul>
<li><strong>Установка сессии — PQXDH.</strong> X25519 вместе с ML-KEM (Kyber). Постквантовая половина важна потому, что перехваченный сегодня трафик можно сохранить и взломать позже.</li>
<li><strong>Дальше — Double Ratchet («двойной храповик»).</strong> Каждое сообщение шифруется новым ключом. Два храповика: один проворачивается на каждое сообщение, второй — на каждый ответ. Укравший сегодняшний ключ получает одно сообщение: ни переписку до него (forward secrecy), ни после (восстановление после компрометации).</li>
<li><strong>Sealed sender.</strong> Личность отправителя лежит внутри шифртекста, а не на конверте. Шлюз не видит, кто что отправил.</li>
<li><strong>Среднесрочные ключи меняются каждые 48 ч.</strong></li>
</ul>
<p>Каждый конверт — ровно <strong>8192 байта</strong>, а полезная нагрузка внутри дополняется до <strong>5888 байт ещё до шифрования</strong>, поэтому длина не говорит о сообщении ничего. Максимум 4096 байт на сообщение.</p>
<hr>
<h2 id="korziny-buckets" class="atx">Корзины (buckets)</h2>
<p>У аккаунтов нет личных почтовых ящиков. <strong>Один ящик на 16 аккаунтов.</strong></p>
<p>Каждый участник скачивает все конверты своей корзины и пробует расшифровать. Чужое просто не открывается и молча отбрасывается.</p>
<p>Поэтому шлюз узнаёт лишь «один из этих 16 что-то получил» — но не кто именно. В этом молчании весь смысл.</p>
<p>Цена: вы скачиваете и чужой трафик. Это и есть плата за размер анонимного множества.</p>
<hr>
<h2 id="dokazatelstvo-raboty" class="atx">Доказательство работы</h2>
<p>Каждая отправка несёт вычисление, привязанное к корзине и к конкретному шифртексту, — около 150 мс, сложность 16. Регистрация дороже: 18.</p>
<p>Личности отправителя, которую можно было бы ограничивать, здесь нет — так задумано. Поэтому флуд не запрещают, а делают дорогим: по мере расходования общего бюджета корзины требуемая работа растёт вплоть до 64×.</p>
<hr>
<h2 id="gruppy" class="atx">Группы</h2>
<p>Группа — это <strong>не объект на сервере.</strong> Это метка, о которой договорились несколько клиентов и которую каждый хранит у себя.</p>
<ul>
<li>Создание группы отправляет список участников каждому из них обычным сообщением.</li>
<li>Отправка рассылает по одной зашифрованной копии каждому. Шлюз видит несвязанные сообщения.</li>
<li>Максимум 50 участников.</li>
<li>Участники выбираются из тех, с кем вы уже переписываетесь: в группе не может быть человека, чьи ключи вы никогда не получали.</li>
<li><strong>Выйти можно. Удалить у всех — нет</strong>: удалять на сервере нечего, и нет сообщения, которое заставит других забыть свою копию.</li>
</ul>
<hr>
<h2 id="hranenie" class="atx">Хранение</h2>
<p>Недоставленные конверты удаляются через <strong>14 дней</strong>. Ничего не архивируется.</p>
<h2 id="licenziya" class="atx">Лицензия</h2>
<p>AGPL-3.0-only, унаследована от libsignal. Раздел 13 обя<strong>зывает любого, кто запускает это как сервис, предоставлять исходный код той версии, которую он запускает.</strong></p>



<h2>Smile - English </h2>
<p>End-to-end encrypted messenger. The server is designed to be useless to whoever runs it.</p>
<hr>
<h2 id="architecture" class="atx">Architecture</h2>
<p>Two services, meant to be run by <strong>two different operators</strong>. Run by one, the relay buys nothing.</p>
<pre><code class="fenced-code-block">phone ──HTTPS──▶ relay ──HTTPS──▶ gateway
                (sees IP,        (sees request,
                 not content)     not IP)</code></pre>
<ul>
<li><strong>Gateway</strong> — stores envelopes, serves them per bucket. Never sees plaintext. Keeps no access log.</li>
<li><strong>Relay</strong> — takes a blob sealed to the gateway's key (HPKE) and forwards it. Sees your address, never your content.</li>
</ul>
<p>Neither half alone links a sender to a recipient.</p>
<h3 id="configuration" class="atx">Configuration</h3>
<table>
<thead>
<tr>
<th></th>
<th>Gateway</th>
<th>Relay</th>
</tr>
</thead>
<tbody><tr>
<td>Listens</td>
<td><code>127.0.0.1:8443</code></td>
<td><code>127.0.0.1:8444</code></td>
</tr>
<tr>
<td>Public</td>
<td><code>https://your-gateway.example</code></td>
<td><code>https://your-relay.example</code></td>
</tr>
<tr>
<td>Needs</td>
<td>TLS reverse proxy</td>
<td>TLS reverse proxy, <code>MG_GATEWAY_URL</code></td>
</tr>
</tbody></table>
<p>TLS must terminate at a proxy in front — the app refuses cleartext and trusts only the system CA store.</p>
<pre><code class="fenced-code-block">MG_BUCKET_SIZE=16        # accounts sharing one mailbox
MG_POW_DIFFICULTY=16     # work per message
MG_DB=/data/server.db</code></pre>
<p>Turn off proxy access logs. A log of who connected and when is the metadata this design exists not to keep.</p>
<hr>
<h2 id="encryption" class="atx">Encryption</h2>
<p>libsignal, the same library Signal uses.</p>
<ul>
<li><strong>Session setup — PQXDH.</strong> X25519 plus ML-KEM (Kyber). The post-quantum half matters because traffic captured today can be stored and attacked later.</li>
<li><strong>Then — Double Ratchet.</strong> Every message uses a fresh key. Two ratchets: one advances per message, one per reply. Steal today's key and you get one message — not the conversation before it (forward secrecy) and not the one after (post-compromise recovery).</li>
<li><strong>Sealed sender.</strong> The sender's identity is inside the ciphertext, not on the envelope. The gateway cannot see who sent what.</li>
<li><strong>Medium-term keys rotate every 48 h.</strong></li>
</ul>
<p>Every envelope is exactly <strong>8192 bytes</strong>, and the payload inside is padded to <strong>5888 bytes before encryption</strong> — so length reveals nothing about the message. Max message 4096 bytes.</p>
<hr>
<h2 id="buckets" class="atx">Buckets</h2>
<p>Accounts don't have private mailboxes. <strong>16 accounts share one.</strong></p>
<p>Every member downloads every envelope in their bucket and tries to decrypt. Anything not for you simply fails to open, and is dropped without a word.</p>
<p>The gateway therefore learns "one of these 16 received something" — never which one. That silence is the point.</p>
<p>Cost: you download traffic that isn't yours. That is the price of the anonymity set.</p>
<hr>
<h2 id="proof-of-work" class="atx">Proof of work</h2>
<p>Every submission carries work bound to the bucket and the exact ciphertext — about 150 ms, difficulty 16. Registration costs more, 18.</p>
<p>There is no sender identity to rate-limit, by design. So flooding is priced instead: as a bucket's shared budget drains, required work climbs up to 64×.</p>
<hr>
<h2 id="groups" class="atx">Groups</h2>
<p>A group is <strong>not a thing the server has.</strong> It is a label a handful of clients agree to use, held by each of them.</p>
<ul>
<li>Creating one sends the member list to each member as an ordinary message.</li>
<li>Sending fans out one encrypted copy per member. The gateway sees unrelated messages.</li>
<li>Max 50 members.</li>
<li>Members are chosen from people you already message — a group cannot contain someone whose keys you have never fetched.</li>
<li><strong>You can leave. You cannot delete for everyone</strong> — there is no server object to remove and no message that makes others forget theirs.</li>
</ul>
<hr>
<h2 id="retention" class="atx">Retention</h2>
<p>Undelivered envelopes are dropped after <strong>14 days</strong>. Nothing is archived.</p>
<h2 id="licence" class="atx">Licence</h2>
<p>AGPL-3.0-only, inherited from libsignal. Section 13 means anyone running this as a service must offer the source they run.</p>
<hr>



