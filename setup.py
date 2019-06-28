from setuptools import setup, find_packages

desc = "A short-lived certificate tool based on the Zero Trust network mode"

setup(
    name="mtls",
    author="Danny Grove <danny@drgrovellc.com>",
    url="https://github.com/drGrove/mtls-cli",
    description=desc,
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    project_urls={
        "Homepage": "https://github.com/drGrove/mtls-cli",
        "Source": "https://github.com/drGrove/mtls-cli",
        "Tracker": "https://github.com/drGrove/mtls-cli/issues",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Internet",
        "Topic :: Security :: Cryptography",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3 :: Only",
    ],
    python_requires='>=3.6',
    setup_requires=["setuptools_scm"],
    use_scm_version=True,
    packages=find_packages(exclude=["test"]),
    package_data={"mtls": ["share/*"]},
    entry_points={
        "console_scripts": [
            "mtls = mtls.cli:cli"
        ]
    },
    install_requires=[
        "cryptography",
        "python-gnupg",
        "urllib3",
        "requests",
        "click",
        "pyOpenSSL",
    ],
    zip_safe=True
)
