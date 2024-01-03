# Gts.AuthorizationServer
<h3>Get started</h3>
Чтобы запусть сервер авторизации понадобится PostgreSQL
<ol>
<li>Клонируем репозиторий</li>
<li>Переходим в Gts.AuthorizationServer/appsettings.json</li>
<li>В строке 3 меняем строчку под свой серевер, например: "DbConnection": "Host=localhost;Port=5432;Database=GtsAuthorizationServer;User ID=postgres;Password=QWERTy1234;Integrated Security=True;"</li>
<li>Открываем "Консоль диспетчера пакетов" (Средства -> Диспетчер пакетов Nuget -> Консоль диспетчера пакетов)</li>
<li>В консоли прописываем "update-database"</li>
</ol>
<h3>Startup</h3>
Запускаем приложенеи и попадаем на пустую страницу
<ul>
  <li>Для того, чтобы открыть окно администратора, нужно в конец url-ки вставить "/Users"</li>
  <li>Для того, чтобы открыть окно входа, нужно в конец url-ки вставить "/Identity/Account/Login"</li>
  <li>Для того, чтобы открыть окно ркгистрации, нужно в конец url-ки вставить "/Identity/Account/Register"</li>
</ul>
