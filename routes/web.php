<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

/*Route::get('/', function () {
    return view('layouts.app_screen_l3');
});*/

Route::get("/", [\App\Http\Controllers\HomeController::class, 'index'])->name('app.landing-screen');

 



Auth::routes();

Route::post('custom-authenticate', [\App\Http\Controllers\Auth\LoginController::class, 'customAuthenticate'])->name('custom-authenticate');

Route::get('/home', [App\Http\Controllers\HomeController::class, 'index'])->name('home');

Route::prefix('no-auth')->group(function(){

    Route::post('districts-by-province-id', [\App\Http\Controllers\NoAuthActionsControllers::class, 'districtsByProvinceId'])->name('noauth.districts-by-province-id');

    Route::post('districts-by-division-id', [\App\Http\Controllers\NoAuthActionsControllers::class, 'districtsByDivisionId'])->name('noauth.districts-by-division-id');

    Route::post('tehsils-by-district-id', [\App\Http\Controllers\NoAuthActionsControllers::class, 'tehsilsByDistrictId'])->name('noauth.tehsils-by-district-id');

    Route::post('sections-by-company-id', [\App\Http\Controllers\NoAuthActionsControllers::class, 'sectionsByCompanyId'])->name('noauth.sections-by-company-id');

    Route::post('users-list-by-company-id', [\App\Http\Controllers\NoAuthActionsControllers::class, 'usersListByCompanyId'])->name('noauth.users-list-by-company-id');

    Route::post('companies-by-type-id', [\App\Http\Controllers\NoAuthActionsControllers::class, 'companiesByTypeId'])->name('noauth.companies-by-type-id');

});

Route::get('/psw-generate', function(){
    return \Illuminate\Support\Facades\Hash::make('12345678');
});