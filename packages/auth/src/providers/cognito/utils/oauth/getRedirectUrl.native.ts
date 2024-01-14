// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { invalidRedirectException } from '../../../../errors/constants';

/** @internal */
export function getRedirectUrl(redirects: string[]): string {
	const redirect = redirects?.find(
		redirect =>
			!redirect.startsWith('http://') && !redirect.startsWith('https://') && !redirect.startsWith('anyspaces://')
	);
	if (!redirect) {
		throw invalidRedirectException;
	}
	return redirect;
}
