<?php

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

Route::prefix('settings')->group(function() {

    Route::get('/', 'MyAppsController@index')->name('settings.home');

    Route::prefix('my-apps')->group(function (){


        Route::get('/', [\Modules\Settings\Http\Controllers\MyAppsController::class, 'index'])
            ->name('settings.my-apps.list')
            ->middleware('permission:apps.view');

        Route::group(['middleware' => ['permission:apps.create']], function(){
            Route::get('create', [\Modules\Settings\Http\Controllers\MyAppsController::class, 'create'])->name('settings.my-apps.create');
            Route::post('store', [\Modules\Settings\Http\Controllers\MyAppsController::class, 'store'])->name('settings.my-apps.store');
        });

        Route::group(['middleware' => ['permission:apps.edit']], function(){
            Route::get('edit/{id}', [\Modules\Settings\Http\Controllers\MyAppsController::class, 'edit'])->name('settings.my-apps.edit');
            Route::put('update/{id}', [\Modules\Settings\Http\Controllers\MyAppsController::class, 'update'])->name('settings.my-apps.update');
        });


        Route::delete('delete/{id}', [\Modules\Settings\Http\Controllers\MyAppsController::class, 'destroy'])->name('settings.my-apps.delete')->middleware('permission:apps.delete');

    });


    Route::prefix('menus')->group(function (){

        Route::get('/', [\Modules\Settings\Http\Controllers\MenusController::class, 'index'])->name('settings.menus.list');

        Route::get('create', [\Modules\Settings\Http\Controllers\MenusController::class, 'create'])->name('settings.menus.create');
        Route::post('store', [\Modules\Settings\Http\Controllers\MenusController::class, 'store'])->name('settings.menus.store');

        Route::get('edit/{id}', [\Modules\Settings\Http\Controllers\MenusController::class, 'edit'])->name('settings.menus.edit');
        Route::put('update/{id}', [\Modules\Settings\Http\Controllers\MenusController::class, 'update'])->name('settings.menus.update');

        Route::delete('delete/{id}', [\Modules\Settings\Http\Controllers\MenusController::class, 'destroy'])->name('settings.menus.delete');

        Route::post('menus-by-app-id', [\Modules\Settings\Http\Controllers\MenusController::class, 'menuByAppId'])->name('settings.menus.menus-by-app-id');

    });


    Route::prefix('my-permissions')->group(function (){

        Route::get('/', [\Modules\Settings\Http\Controllers\MyPermissionsController::class, 'index'])->name('settings.my-permissions.list');

        Route::get('create', [\Modules\Settings\Http\Controllers\MyPermissionsController::class, 'create'])->name('settings.my-permissions.create');
        Route::post('store', [\Modules\Settings\Http\Controllers\MyPermissionsController::class, 'store'])->name('settings.my-permissions.store');

        Route::get('edit/{id}', [\Modules\Settings\Http\Controllers\MyPermissionsController::class, 'edit'])->name('settings.my-permissions.edit');
        Route::put('update/{id}', [\Modules\Settings\Http\Controllers\MyPermissionsController::class, 'update'])->name('settings.my-permissions.update');

        Route::delete('delete/{id}', [\Modules\Settings\Http\Controllers\MyPermissionsController::class, 'destroy'])->name('settings.my-permissions.delete');

    });


    Route::prefix('my-roles')->group(function (){

        Route::get('/', [\Modules\Settings\Http\Controllers\MyRolesController::class, 'index'])->name('settings.my-roles.list');

        Route::get('role-permissions/{id}', [\Modules\Settings\Http\Controllers\MyRolesController::class, 'show'])->name('settings.my-roles.show');
        Route::post('role-permissions-save/{id}', [\Modules\Settings\Http\Controllers\MyRolesController::class, 'rolePermissionsSave'])->name('settings.my-roles.role-permissions-save');

        Route::get('create', [\Modules\Settings\Http\Controllers\MyRolesController::class, 'create'])->name('settings.my-roles.create');
        Route::post('store', [\Modules\Settings\Http\Controllers\MyRolesController::class, 'store'])->name('settings.my-roles.store');

        Route::get('edit/{id}', [\Modules\Settings\Http\Controllers\MyRolesController::class, 'edit'])->name('settings.my-roles.edit');
        Route::put('update/{id}', [\Modules\Settings\Http\Controllers\MyRolesController::class, 'update'])->name('settings.my-roles.update');

        Route::delete('delete/{id}', [\Modules\Settings\Http\Controllers\MyRolesController::class, 'destroy'])->name('settings.my-roles.delete');

    });


    Route::prefix('companies')->group(function (){

        Route::get('/', [\Modules\Settings\Http\Controllers\CompaniesController::class, 'index'])->name('settings.companies.list');

        Route::get('create', [\Modules\Settings\Http\Controllers\CompaniesController::class, 'create'])->name('settings.companies.create');
        Route::post('store', [\Modules\Settings\Http\Controllers\CompaniesController::class, 'store'])->name('settings.companies.store');

        Route::get('edit/{id}', [\Modules\Settings\Http\Controllers\CompaniesController::class, 'edit'])->name('settings.companies.edit');
        Route::put('update/{id}', [\Modules\Settings\Http\Controllers\CompaniesController::class, 'update'])->name('settings.companies.update');

        Route::delete('delete/{id}', [\Modules\Settings\Http\Controllers\CompaniesController::class, 'destroy'])->name('settings.companies.delete');

    });


    Route::prefix('company-types')->group(function (){

        Route::get('/', [\Modules\Settings\Http\Controllers\CompanyTypesController::class, 'index'])->name('settings.company-types.list');

        Route::get('create', [\Modules\Settings\Http\Controllers\CompanyTypesController::class, 'create'])->name('settings.company-types.create');
        Route::post('store', [\Modules\Settings\Http\Controllers\CompanyTypesController::class, 'store'])->name('settings.company-types.store');

        Route::get('edit/{id}', [\Modules\Settings\Http\Controllers\CompanyTypesController::class, 'edit'])->name('settings.company-types.edit');
        Route::put('update/{id}', [\Modules\Settings\Http\Controllers\CompanyTypesController::class, 'update'])->name('settings.company-types.update');

        Route::delete('delete/{id}', [\Modules\Settings\Http\Controllers\CompanyTypesController::class, 'destroy'])->name('settings.company-types.delete');

    });


    Route::prefix('sections')->group(function (){

        Route::get('/', [\Modules\Settings\Http\Controllers\SectionsController::class, 'index'])->name('settings.sections.list');

        Route::get('create', [\Modules\Settings\Http\Controllers\SectionsController::class, 'create'])->name('settings.sections.create');
        Route::post('store', [\Modules\Settings\Http\Controllers\SectionsController::class, 'store'])->name('settings.sections.store');

        Route::get('edit/{id}', [\Modules\Settings\Http\Controllers\SectionsController::class, 'edit'])->name('settings.sections.edit');
        Route::put('update/{id}', [\Modules\Settings\Http\Controllers\SectionsController::class, 'update'])->name('settings.sections.update');

        Route::delete('delete/{id}', [\Modules\Settings\Http\Controllers\SectionsController::class, 'destroy'])->name('settings.sections.delete');

    });


    Route::prefix('users-mgt')->group(function (){

        Route::get('/', [\Modules\Settings\Http\Controllers\UsersController::class, 'index'])->name('settings.users-mgt.list');

        Route::get('user-permissions/{id}', [\Modules\Settings\Http\Controllers\UsersController::class, 'show'])->name('settings.users-mgt.show');
        Route::post('user-permissions-save/{id}', [\Modules\Settings\Http\Controllers\UsersController::class, 'userPermissionsSave'])->name('settings.users-mgt.user-permissions-save');

        Route::get('create', [\Modules\Settings\Http\Controllers\UsersController::class, 'create'])->name('settings.users-mgt.create');
        Route::post('store', [\Modules\Settings\Http\Controllers\UsersController::class, 'store'])->name('settings.users-mgt.store');

        Route::get('edit/{id}', [\Modules\Settings\Http\Controllers\UsersController::class, 'edit'])->name('settings.users-mgt.edit');
        Route::put('update/{id}', [\Modules\Settings\Http\Controllers\UsersController::class, 'update'])->name('settings.users-mgt.update');

        Route::delete('delete/{id}', [\Modules\Settings\Http\Controllers\UsersController::class, 'destroy'])->name('settings.users-mgt.delete');

        Route::get('my-profile', [\Modules\Settings\Http\Controllers\UsersController::class, 'myProfile'])->name('settings.users-mgt.my-profile');

        Route::post('my-profile-save', [\Modules\Settings\Http\Controllers\UsersController::class, 'myProfileAct'])->name('settings.users-mgt.my-profile-save');

        Route::get('change-password', [\Modules\Settings\Http\Controllers\UsersController::class, 'changePassword'])->name('settings.users-mgt.change-password');

        Route::post('change-password-save', [\Modules\Settings\Http\Controllers\UsersController::class, 'changePasswordAct'])->name('settings.users-mgt.change-password-save');

    });


});
