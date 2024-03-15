FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER app
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["Gts.AuthorizationServer/Gts.AuthorizationServer.csproj", "Gts.AuthorizationServer/"]
RUN dotnet restore "./Gts.AuthorizationServer/./Gts.AuthorizationServer.csproj"
COPY . .
WORKDIR "/src/Gts.AuthorizationServer"
RUN dotnet build "./Gts.AuthorizationServer.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Gts.AuthorizationServer.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
COPY ["Gts.AuthorizationServer/Keys", "Keys/"]
ENTRYPOINT ["dotnet", "Gts.AuthorizationServer.dll"]