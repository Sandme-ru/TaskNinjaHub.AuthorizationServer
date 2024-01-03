FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY Gts.AuthorizationServer/*.csproj /src/Gts.AuthorizationServer/
RUN dotnet restore "/src/Gts.AuthorizationServer/Gts.AuthorizationServer.csproj"
COPY . .
WORKDIR "/src/Gts.AuthorizationServer"
RUN dotnet build "Gts.AuthorizationServer.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Gts.AuthorizationServer.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Gts.AuthorizationServer.dll"]
