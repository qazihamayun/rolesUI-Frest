@extends('layouts.app_screen_frest_vms')
@php $app_id = config('vms.app_id') @endphp

@section('title', 'Edit Branch')


@section('content')
    <livewire:branch.form :model=$model type='update' />

@endsection
